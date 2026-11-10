using System.Threading.RateLimiting;
using Azure.Monitor.OpenTelemetry.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using OpenTelemetry.Instrumentation.AspNetCore;
using OpenTelemetry.Trace;
using XrCopilotLab.Intrusion.Mcp.Core.Analysis;
using XrCopilotLab.Intrusion.Mcp.Core.Geo;
using XrCopilotLab.Intrusion.Mcp.Core.Queries;
using XrCopilotLab.Intrusion.Mcp.Core.Simulation;
using XrCopilotLab.Intrusion.Mcp.Core.Sources;
using XrCopilotLab.Intrusion.Mcp.Server;
using XrCopilotLab.Intrusion.Mcp.Server.Authentication;
using XrCopilotLab.Intrusion.Mcp.Server.Sources;
using XrCopilotLab.Intrusion.Mcp.Server.Tools;

var builder = WebApplication.CreateBuilder(args);

var server = builder.Configuration.GetSection(ServerOptions.SectionName).Get<ServerOptions>() ?? new ServerOptions();
server.Validate();
var policy = builder.Configuration.GetSection(IntrusionPolicy.SectionName).Get<IntrusionPolicy>() ?? new IntrusionPolicy();
builder.Services.AddSingleton(server);
builder.Services.AddSingleton(policy);
builder.Services.AddSingleton(TimeProvider.System);

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
}
else
{
    var logs = builder.Configuration.GetSection(LogFileOptions.SectionName).Get<LogFileOptions>() ?? new LogFileOptions();
    var geo = builder.Configuration.GetSection(GeoOptions.SectionName).Get<GeoOptions>() ?? new GeoOptions();
    builder.Services.AddSingleton<ILogSource>(sp => new FileLogSource(logs, sp.GetRequiredService<ILogger<FileLogSource>>()));
    builder.Services.AddSingleton<IGeoLocator>(sp => GeoDatabaseLoader.Load(geo, sp.GetRequiredService<ILoggerFactory>().CreateLogger("Geo")));
}
builder.Services.AddSingleton<IntrusionQueries>();
builder.Services.AddScoped<IntrusionTools>();

// Stateless HTTP transport: nothing is kept between calls, so the Container App of the demo scales to zero.
builder.Services.AddMcpServer().WithHttpTransport(o => o.Stateless = true).WithTools<IntrusionTools>();

var aiConn = builder.Configuration["APPLICATIONINSIGHTS_CONNECTION_STRING"];
builder.Services.Configure<AspNetCoreTraceInstrumentationOptions>(o => o.Filter = ctx => !ctx.Request.Path.StartsWithSegments("/healthz"));
var otel = builder.Services.AddOpenTelemetry().WithTracing(t => t.AddAspNetCoreInstrumentation());
if (!string.IsNullOrWhiteSpace(aiConn)) otel.UseAzureMonitor(o => o.ConnectionString = aiConn);

var app = builder.Build();

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

app.Logger.LogInformation("Intrusion MCP server: mode {Mode}, host {Host}, {Keys} active key(s)",
    server.Mode, app.Services.GetRequiredService<ILogSource>().Hostname,
    app.Services.GetRequiredService<IOptionsMonitor<ApiKeyOptions>>().CurrentValue.ActiveKeys().Count());

app.Run();

public partial class Program;
