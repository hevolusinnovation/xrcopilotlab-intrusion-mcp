using System.Threading.RateLimiting;
using Azure.Monitor.OpenTelemetry.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using OpenTelemetry.Instrumentation.AspNetCore;
using OpenTelemetry.Trace;
using XrCopilotLab.Intrusion.Mcp.Core.Advice;
using XrCopilotLab.Intrusion.Mcp.Core.Analysis;
using XrCopilotLab.Intrusion.Mcp.Core.Geo;
using XrCopilotLab.Intrusion.Mcp.Core.Guard;
using XrCopilotLab.Intrusion.Mcp.Core.Queries;
using XrCopilotLab.Intrusion.Mcp.Core.Simulation;
using XrCopilotLab.Intrusion.Mcp.Core.Sources;
using XrCopilotLab.Intrusion.Mcp.Server;
using XrCopilotLab.Intrusion.Mcp.Server.Advice;
using XrCopilotLab.Intrusion.Mcp.Server.Audit;
using XrCopilotLab.Intrusion.Mcp.Server.Authentication;
using XrCopilotLab.Intrusion.Mcp.Server.Sources;
using XrCopilotLab.Intrusion.Mcp.Server.Tools;

// The audit is this same binary, started by root on a timer (… audit): it takes its picture of the host and exits.
if (args is ["audit", ..]) return AuditCollector.Run(args[1..], Console.Out);

var builder = WebApplication.CreateBuilder(args);

var server = builder.Configuration.GetSection(ServerOptions.SectionName).Get<ServerOptions>() ?? new ServerOptions();
server.Validate();
var policy = builder.Configuration.GetSection(IntrusionPolicy.SectionName).Get<IntrusionPolicy>() ?? new IntrusionPolicy();
builder.Services.AddSingleton(server);
builder.Services.AddSingleton(policy);
builder.Services.AddSingleton(TimeProvider.System);
var connection = builder.Configuration.GetSection(ConnectionOptions.SectionName).Get<ConnectionOptions>() ?? new ConnectionOptions();
builder.Services.AddSingleton(connection);

// The key says who may call: XRCopilotLab, with the key registered on the MCP server.
builder.Services.AddOptions<ApiKeyOptions>().Bind(builder.Configuration.GetSection(ApiKeyOptions.SectionName));
builder.Services
    .AddAuthentication(ApiKeyAuthenticationHandler.SchemeName)
    .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(ApiKeyAuthenticationHandler.SchemeName, _ => { });
builder.Services.AddAuthorization(o => o.DefaultPolicy = new AuthorizationPolicyBuilder(ApiKeyAuthenticationHandler.SchemeName).RequireAuthenticatedUser().Build());

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(http =>
    {
        var key = http.User.FindFirst("agent_id")?.Value ?? http.Connection.RemoteIpAddress?.ToString() ?? "anonymous";
        return RateLimitPartition.GetSlidingWindowLimiter(key, _ => new SlidingWindowRateLimiterOptions
        {
            PermitLimit = 120,
            Window = TimeSpan.FromMinutes(1),
            SegmentsPerWindow = 6,
            QueueLimit = 0
        });
    });
});

// Where the events come from, and where the addresses are. The simulated mode has its own invented geography;
// the real mode uses the DB-IP Lite file if one is configured.
if (server.IsSimulated)
{
    var simulation = builder.Configuration.GetSection(SimulationOptions.SectionName).Get<SimulationOptions>() ?? new SimulationOptions();
    builder.Services.AddSingleton<ILogSource>(new SimulatedLogSource(simulation));
    builder.Services.AddSingleton<IGeoLocator>(new SyntheticGeo());
    builder.Services.AddSingleton<IHostInspector>(new SimulatedHostInspector());
}
else
{
    var logs = builder.Configuration.GetSection(LogFileOptions.SectionName).Get<LogFileOptions>() ?? new LogFileOptions();
    var geo = builder.Configuration.GetSection(GeoOptions.SectionName).Get<GeoOptions>() ?? new GeoOptions();
    builder.Services.AddSingleton<ILogSource>(sp => new FileLogSource(logs, sp.GetRequiredService<ILogger<FileLogSource>>()));
    builder.Services.AddSingleton<IHostInspector>(sp => new SystemHostInspector(logs, connection, sp.GetRequiredService<ILogger<SystemHostInspector>>()));
    // Documentation addresses (RFC 5737) never reach a real host from the internet: they are the Docker lab's attackers,
    // and get the invented places of the simulated mode, so the lab's map has cities. Every other address: DB-IP.
    builder.Services.AddSingleton<IGeoLocator>(sp => new DocumentationAwareGeo(GeoDatabaseLoader.Load(geo, sp.GetRequiredService<ILoggerFactory>().CreateLogger("Geo"))));
}
builder.Services.AddSingleton<IntrusionQueries>();
builder.Services.AddSingleton(builder.Configuration.GetSection(SiteOptions.SectionName).Get<SiteOptions>() ?? new SiteOptions());
builder.Services.AddSingleton<ISiteLocation, HttpSiteLocation>();
builder.Services.AddSingleton<GuardQueries>();
builder.Services.AddSingleton(builder.Configuration.GetSection(AdviceOptions.SectionName).Get<AdviceOptions>() ?? new AdviceOptions());
builder.Services.AddSingleton<AdviceStore>();
builder.Services.AddScoped<IntrusionTools>();

// Stateless HTTP transport: nothing is kept between calls, so the Container App of the demo scales to zero.
// The instructions tell the agent, before any answer, that some fields are the attackers' text and not orders.
builder.Services.AddMcpServer(o => o.ServerInstructions = IntrusionTools.Instructions)
    .WithHttpTransport(o => o.Stateless = true).WithTools<IntrusionTools>();

var aiConn = builder.Configuration["APPLICATIONINSIGHTS_CONNECTION_STRING"];
builder.Services.Configure<AspNetCoreTraceInstrumentationOptions>(o => o.Filter = ctx => !ctx.Request.Path.StartsWithSegments("/healthz"));
var otel = builder.Services.AddOpenTelemetry().WithTracing(t => t.AddAspNetCoreInstrumentation());
if (!string.IsNullOrWhiteSpace(aiConn)) otel.UseAzureMonitor(o => o.ConnectionString = aiConn);

var app = builder.Build();

// The monitoring page: static files only, no data in them. Its data comes from /api, with a key (added by the
// package's nginx, or typed by the person when the page is opened directly).
app.UseDefaultFiles();
// The page itself is revalidated on every load (no-cache keeps the ETag, so an unchanged page is a 304): after an
// update the browser shows the new page, not the copy it kept. Its libraries and logo may be cached as usual.
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = ctx =>
    {
        if (ctx.File.Name.EndsWith(".html", StringComparison.OrdinalIgnoreCase))
            ctx.Context.Response.Headers.CacheControl = "no-cache";
    },
});

app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

// Readiness: 503 without a key, since every call would be refused. Says the mode, never the key.
app.MapGet("/healthz", (IOptionsMonitor<ApiKeyOptions> keys, ILogSource source) =>
{
    var ready = keys.CurrentValue.ActiveKeys().Any();
    return Results.Json(new
    {
        status = ready ? "ok" : "not-ready",
        config = ready ? "ok" : "no API key configured (ApiKeys:Hash)",
        mode = server.IsSimulated ? ServerOptions.Simulated : ServerOptions.Logs,
        host = source.Hostname,
        time = DateTimeOffset.UtcNow,
    }, statusCode: ready ? StatusCodes.Status200OK : StatusCodes.Status503ServiceUnavailable);
}).AllowAnonymous();

app.MapGet("/livez", () => Results.Ok(new { status = "ok" })).AllowAnonymous();

app.MapMcp("/mcp").RequireAuthorization();
app.MapRestApi();

app.Logger.LogInformation("Intrusion MCP server: mode {Mode}, host {Host}, {Keys} active key(s)",
    server.Mode, app.Services.GetRequiredService<ILogSource>().Hostname,
    app.Services.GetRequiredService<IOptionsMonitor<ApiKeyOptions>>().CurrentValue.ActiveKeys().Count());

app.Run();
return 0;

public partial class Program;
