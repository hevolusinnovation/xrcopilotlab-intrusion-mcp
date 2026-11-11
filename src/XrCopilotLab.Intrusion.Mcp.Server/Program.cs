using System.Threading.RateLimiting;
using Azure.Monitor.OpenTelemetry.AspNetCore;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using OpenTelemetry.Instrumentation.AspNetCore;
using OpenTelemetry.Trace;
using XrCopilotLab.Intrusion.Mcp.Core.Analysis;
using XrCopilotLab.Intrusion.Mcp.Core.Collector;
using XrCopilotLab.Intrusion.Mcp.Core.Geo;
using XrCopilotLab.Intrusion.Mcp.Core.Queries;
using XrCopilotLab.Intrusion.Mcp.Core.Simulation;
using XrCopilotLab.Intrusion.Mcp.Core.Sources;
using XrCopilotLab.Intrusion.Mcp.Server;
using XrCopilotLab.Intrusion.Mcp.Server.Agent;
using XrCopilotLab.Intrusion.Mcp.Server.Authentication;
using XrCopilotLab.Intrusion.Mcp.Server.Collector;
using XrCopilotLab.Intrusion.Mcp.Server.Sources;
using XrCopilotLab.Intrusion.Mcp.Server.Tools;

var builder = WebApplication.CreateBuilder(args);

var server = builder.Configuration.GetSection(ServerOptions.SectionName).Get<ServerOptions>() ?? new ServerOptions();
server.Validate();

// The agent runs on the customer's host and only sends: no web server, no port.
if (server.IsAgent)
{
    var agentHost = Host.CreateApplicationBuilder(args);
    var agent = agentHost.Configuration.GetSection(AgentOptions.SectionName).Get<AgentOptions>() ?? new AgentOptions();
    agent.Validate();
    agentHost.Services.AddSingleton(Options.Create(agent));
    agentHost.Services.AddSingleton(TimeProvider.System);
    agentHost.Services.AddHttpClient(AgentWorker.ClientName, c => AgentWorker.Configure(c, agent));
    agentHost.Services.AddHostedService<AgentWorker>();
    agentHost.Build().Run();
    return;
}

var policy = builder.Configuration.GetSection(IntrusionPolicy.SectionName).Get<IntrusionPolicy>() ?? new IntrusionPolicy();
builder.Services.AddSingleton(server);
builder.Services.AddSingleton(policy);
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddHttpContextAccessor();

// Two kinds of key: XRCopilotLab reads (role query, one tenant), an agent writes (role ingest, one host).
builder.Services.AddOptions<ApiKeyOptions>().Bind(builder.Configuration.GetSection(ApiKeyOptions.SectionName));
builder.Services.AddOptions<CollectorOptions>().Bind(builder.Configuration.GetSection(CollectorOptions.SectionName));
builder.Services
    .AddAuthentication(ApiKeyAuthenticationHandler.SchemeName)
    .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(ApiKeyAuthenticationHandler.SchemeName, _ => { });
builder.Services.AddAuthorization(o =>
{
    o.AddPolicy(KeyPolicies.Query, p => p.AddAuthenticationSchemes(ApiKeyAuthenticationHandler.SchemeName).RequireClaim(KeyClaims.Role, KeyRoles.Query));
    o.AddPolicy(KeyPolicies.Ingest, p => p.AddAuthenticationSchemes(ApiKeyAuthenticationHandler.SchemeName).RequireClaim(KeyClaims.Role, KeyRoles.Ingest));
    o.DefaultPolicy = o.GetPolicy(KeyPolicies.Query)!;
});

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(http =>
    {
        var key = http.User.FindFirst(KeyClaims.AgentId)?.Value ?? http.Connection.RemoteIpAddress?.ToString() ?? "anonymous";
        return RateLimitPartition.GetSlidingWindowLimiter(key, _ => new SlidingWindowRateLimiterOptions
        {
            PermitLimit = 120,
            Window = TimeSpan.FromMinutes(1),
            SegmentsPerWindow = 6,
            QueueLimit = 0
        });
    });
});

// Where the events come from, and where the addresses are. The simulated mode has its own invented geography; the
// real mode uses the DB-IP Lite file if one is configured; the collector both, by address range.
var simulation = builder.Configuration.GetSection(SimulationOptions.SectionName).Get<SimulationOptions>() ?? new SimulationOptions();
var geoOptions = builder.Configuration.GetSection(GeoOptions.SectionName).Get<GeoOptions>() ?? new GeoOptions();
if (server.IsSimulated)
{
    var source = new SimulatedLogSource(simulation);
    builder.Services.AddSingleton<ILogSource>(source);
    builder.Services.AddSingleton<ISourceResolver>(new SingleSourceResolver(source));
    builder.Services.AddSingleton<IGeoLocator>(new SyntheticGeo());
}
else if (server.IsCollector)
{
    var collector = builder.Configuration.GetSection(CollectorOptions.SectionName).Get<CollectorOptions>() ?? new CollectorOptions();
    builder.Services.AddSingleton<IByteLogStore>(_ => string.Equals(collector.Store, CollectorOptions.BlobStore, StringComparison.OrdinalIgnoreCase)
        ? new BlobByteLogStore(new BlobContainerClient(
            collector.BlobConnectionString ?? throw new InvalidOperationException("Collector:BlobConnectionString is not set"), collector.BlobContainer))
        : new FileByteLogStore(collector.StorePath));
    builder.Services.AddSingleton(sp => new StoredEvents(sp.GetRequiredService<IByteLogStore>(), collector.RetentionDays));
    builder.Services.AddSingleton<ISourceResolver>(sp => new CollectorSourceResolver(
        sp.GetRequiredService<IOptionsMonitor<CollectorOptions>>(), sp.GetRequiredService<StoredEvents>(),
        collector.SimulatedTenants.Count > 0 ? new SimulatedLogSource(simulation) : null));
    builder.Services.AddSingleton<IGeoLocator>(sp => new DocumentationAwareGeo(
        GeoDatabaseLoader.Load(geoOptions, sp.GetRequiredService<ILoggerFactory>().CreateLogger("Geo"))));
    builder.Services.AddHostedService<CollectorMaintenance>();
}
else
{
    var logs = builder.Configuration.GetSection(LogFileOptions.SectionName).Get<LogFileOptions>() ?? new LogFileOptions();
    builder.Services.AddSingleton<ILogSource>(sp => new FileLogSource(logs, sp.GetRequiredService<ILogger<FileLogSource>>()));
    builder.Services.AddSingleton<ISourceResolver>(sp => new SingleSourceResolver(sp.GetRequiredService<ILogSource>()));
    builder.Services.AddSingleton<IGeoLocator>(sp => GeoDatabaseLoader.Load(geoOptions, sp.GetRequiredService<ILoggerFactory>().CreateLogger("Geo")));
}
builder.Services.AddSingleton<QueryScope>();
builder.Services.AddScoped<IntrusionTools>();

// Stateless HTTP transport: nothing is kept between calls, so the Container App scales to zero.
builder.Services.AddMcpServer().WithHttpTransport(o => o.Stateless = true).WithTools<IntrusionTools>();

var aiConn = builder.Configuration["APPLICATIONINSIGHTS_CONNECTION_STRING"];
builder.Services.Configure<AspNetCoreTraceInstrumentationOptions>(o => o.Filter = ctx => !ctx.Request.Path.StartsWithSegments("/healthz"));
var otel = builder.Services.AddOpenTelemetry().WithTracing(t => t.AddAspNetCoreInstrumentation());
if (!string.IsNullOrWhiteSpace(aiConn)) otel.UseAzureMonitor(o => o.ConnectionString = aiConn);

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

// Readiness: 503 without a key, since every call would be refused. Says the mode, never a key.
app.MapGet("/healthz", (IOptionsMonitor<ApiKeyOptions> keys, IOptionsMonitor<CollectorOptions> hosts) =>
{
    var ready = keys.CurrentValue.ActiveKeys().Any();
    return Results.Json(new
    {
        status = ready ? "ok" : "not-ready",
        config = ready ? "ok" : "no API key configured (ApiKeys:Hash)",
        mode = server.Mode.ToLowerInvariant(),
        agents = server.IsCollector ? hosts.CurrentValue.ActiveHosts().Count() : (int?)null,
        time = DateTimeOffset.UtcNow,
    }, statusCode: ready ? StatusCodes.Status200OK : StatusCodes.Status503ServiceUnavailable);
}).AllowAnonymous();

app.MapGet("/livez", () => Results.Ok(new { status = "ok" })).AllowAnonymous();

app.MapMcp("/mcp").RequireAuthorization(KeyPolicies.Query);
app.MapRestApi();
if (server.IsCollector) app.MapIngest();

app.Logger.LogInformation("Intrusion MCP server: mode {Mode}, {Keys} read key(s), {Agents} agent key(s)",
    server.Mode, app.Services.GetRequiredService<IOptionsMonitor<ApiKeyOptions>>().CurrentValue.ActiveKeys().Count(),
    app.Services.GetRequiredService<IOptionsMonitor<CollectorOptions>>().CurrentValue.ActiveHosts().Count());

app.Run();

public partial class Program;
