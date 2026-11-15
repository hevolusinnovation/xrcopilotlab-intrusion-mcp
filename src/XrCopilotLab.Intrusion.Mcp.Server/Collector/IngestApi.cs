using Microsoft.AspNetCore.Mvc;
using XrCopilotLab.Intrusion.Mcp.Core.Collector;
using XrCopilotLab.Intrusion.Mcp.Server.Authentication;

namespace XrCopilotLab.Intrusion.Mcp.Server.Collector;

/// <summary>
/// <c>POST /ingest</c>: where agents send their lines, with an agent key. The host and tenant come from the key, never
/// from the body. Only in the collector mode.
/// </summary>
public static class IngestApi
{
    public const long MaxBodyBytes = 16 * 1024 * 1024;

    public static void MapIngest(this WebApplication app)
    {
        app.MapPost("/ingest", async (HttpContext http, [FromBody] IngestRequest? body, StoredEvents store, TimeProvider clock, ILoggerFactory loggers, CancellationToken ct) =>
        {
            var error = IngestRules.Validate(body);
            if (error is not null) return Results.BadRequest(new { error });

            var tenant = http.User.FindFirst(KeyClaims.Tenant)!.Value;
            var host = http.User.FindFirst(KeyClaims.Host)!.Value;
            var result = await store.IngestAsync(tenant, host, body!, clock.GetUtcNow(), ct);
            loggers.CreateLogger("Ingest").LogInformation("Ingest {Tenant}/{Host}: {Received} lines received, {Stored} stored (agent {Agent})",
                tenant, host, result.Received, result.Stored, body!.Agent);
            return Results.Ok(result);
        })
        .RequireAuthorization(KeyPolicies.Ingest)
        .WithMetadata(new RequestSizeLimitAttribute(MaxBodyBytes));
    }
}

/// <summary>Deletes the days past the retention every six hours, while the collector is up.</summary>
public sealed class CollectorMaintenance(StoredEvents store, TimeProvider clock, ILogger<CollectorMaintenance> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var deleted = await store.PurgeAsync(clock.GetUtcNow(), stoppingToken);
                if (deleted > 0) logger.LogInformation("Retention: {Deleted} files deleted", deleted);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Retention pass failed");
            }
            await Task.Delay(TimeSpan.FromHours(6), stoppingToken);
        }
    }
}
