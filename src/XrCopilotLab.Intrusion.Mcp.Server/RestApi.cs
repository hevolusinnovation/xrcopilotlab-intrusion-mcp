using XrCopilotLab.Intrusion.Mcp.Core.Advice;
using XrCopilotLab.Intrusion.Mcp.Core.Guard;
using XrCopilotLab.Intrusion.Mcp.Core.Queries;
using XrCopilotLab.Intrusion.Mcp.Server.Advice;

namespace XrCopilotLab.Intrusion.Mcp.Server;

/// <summary>
/// The same answers as the MCP tools, as plain HTTP GETs under <c>/api</c>, with the same key. A blueprint can only
/// provision an MCP server it builds itself (<c>kind: builder</c>, HTTP calls on a connection): with this face the
/// whole sentinel module installs from the manifest, with no step in the UI. The MCP face stays for whoever
/// registers the server by hand.
/// </summary>
public static class RestApi
{
    public static void MapRestApi(this WebApplication app)
    {
        var api = app.MapGroup("/api").RequireAuthorization();

        api.MapGet("/status", (IntrusionQueries q, TimeProvider clock) => q.Status(clock.GetUtcNow()));

        api.MapGet("/banned", (IntrusionQueries q, TimeProvider clock, string? jail) =>
            q.Banned(clock.GetUtcNow(), Blank(jail)));

        api.MapGet("/attempts", (IntrusionQueries q, TimeProvider clock, int? hours, DateTimeOffset? since, DateTimeOffset? until, int? slotMinutes,
                string? jail, string? attackType, string? country, int? top) =>
        {
            var now = clock.GetUtcNow();
            return q.Attempts(now, q.Resolve(now, hours, since, until, slotMinutes), Blank(jail), Blank(attackType), Blank(country), top ?? 20);
        });

        api.MapGet("/ips/{ip}", (IntrusionQueries q, TimeProvider clock, string ip, int? hours, DateTimeOffset? since, DateTimeOffset? until) =>
        {
            var now = clock.GetUtcNow();
            return q.IpDetail(now, q.Resolve(now, hours, since, until), ip.Trim());
        });

        api.MapGet("/suspicious-logins", (IntrusionQueries q, TimeProvider clock, int? hours, DateTimeOffset? since, DateTimeOffset? until, int? slotMinutes) =>
        {
            var now = clock.GetUtcNow();
            return q.SuspiciousLogins(now, q.Resolve(now, hours, since, until, slotMinutes));
        });

        api.MapGet("/summary", (IntrusionQueries q, TimeProvider clock, int? hours, DateTimeOffset? since, DateTimeOffset? until, int? slotMinutes, int? top) =>
        {
            var now = clock.GetUtcNow();
            return q.Summary(now, q.Resolve(now, hours, since, until, slotMinutes), top ?? 10);
        });

        api.MapGet("/host-activity", (IntrusionQueries q, TimeProvider clock, int? hours, DateTimeOffset? since, DateTimeOffset? until, int? slotMinutes,
            string? attackType, bool? unlinkedOnly) =>
        {
            var now = clock.GetUtcNow();
            return q.HostActivity(now, q.Resolve(now, hours, since, until, slotMinutes), Blank(attackType), unlinkedOnly ?? false);
        });

        api.MapGet("/guardians", (GuardQueries g, TimeProvider clock) => g.Guardians(clock.GetUtcNow()));

        api.MapGet("/vpn", (GuardQueries g, TimeProvider clock) => g.Vpn(clock.GetUtcNow()));

        api.MapGet("/posture", (GuardQueries g, IntrusionQueries q, TimeProvider clock, int? hours, DateTimeOffset? since, DateTimeOffset? until) =>
        {
            var now = clock.GetUtcNow();
            return g.Posture(now, q.Resolve(now, hours ?? GuardQueries.DefaultPostureHours, since, until));
        });

        // The one write face: the SOC process posts advice a person approved, so the page and the agent can show what
        // has been decided. It is only stored and shown — the toolkit never applies it or runs a command.
        var advice = api.MapGroup("/advice");

        advice.MapPost("", (AdviceRequest body, AdviceStore store, TimeProvider clock) =>
        {
            try
            {
                var (item, created) = store.Upsert(body, clock.GetUtcNow());
                return Results.Json(
                    new { id = item.Id, status = created ? "received" : "updated" },
                    statusCode: created ? StatusCodes.Status201Created : StatusCodes.Status200OK);
            }
            catch (AdviceValidationException ex)
            {
                return Results.Problem(detail: ex.Message, statusCode: StatusCodes.Status400BadRequest);
            }
        }).AddEndpointFilter(RejectOversized);

        advice.MapGet("", (AdviceStore store, TimeProvider clock, int? hours) => store.List(clock.GetUtcNow(), hours));

        advice.MapPost("/{id}/done", (string id, AdviceStore store, TimeProvider clock) =>
            store.MarkDone(id, clock.GetUtcNow())
                ? Results.Ok(new { id = id.Trim(), status = AdviceLimits.StatusDone })
                : Results.NotFound());
    }

    // 413 for a body over the cap, before the handler runs. The caller is trusted (it has the key); this guards a mistake.
    private static async ValueTask<object?> RejectOversized(EndpointFilterInvocationContext ctx, EndpointFilterDelegate next)
    {
        if (ctx.HttpContext.Request.ContentLength is long len && len > AdviceLimits.MaxBodyBytes)
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
        return await next(ctx);
    }

    // A builder tool sends an empty value for an argument the model left out: treat it as no filter.
    private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
