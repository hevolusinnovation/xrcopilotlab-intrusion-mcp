using XrCopilotLab.Intrusion.Mcp.Core.Queries;

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

        api.MapGet("/attempts", (IntrusionQueries q, TimeProvider clock, int? hours, DateTimeOffset? since, DateTimeOffset? until,
                string? jail, string? attackType, string? country, int? top) =>
        {
            var now = clock.GetUtcNow();
            return q.Attempts(now, q.Resolve(now, hours, since, until), Blank(jail), Blank(attackType), Blank(country), top ?? 20);
        });

        api.MapGet("/ips/{ip}", (IntrusionQueries q, TimeProvider clock, string ip, int? hours, DateTimeOffset? since, DateTimeOffset? until) =>
        {
            var now = clock.GetUtcNow();
            return q.IpDetail(now, q.Resolve(now, hours, since, until), ip.Trim());
        });

        api.MapGet("/suspicious-logins", (IntrusionQueries q, TimeProvider clock, int? hours, DateTimeOffset? since, DateTimeOffset? until) =>
        {
            var now = clock.GetUtcNow();
            return q.SuspiciousLogins(now, q.Resolve(now, hours, since, until));
        });

        api.MapGet("/summary", (IntrusionQueries q, TimeProvider clock, int? hours, DateTimeOffset? since, DateTimeOffset? until, int? top) =>
        {
            var now = clock.GetUtcNow();
            return q.Summary(now, q.Resolve(now, hours, since, until), top ?? 10);
        });
    }

    // A builder tool sends an empty value for an argument the model left out: treat it as no filter.
    private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
