using XrCopilotLab.Intrusion.Mcp.Core.Queries;
using XrCopilotLab.Intrusion.Mcp.Server.Authentication;
using XrCopilotLab.Intrusion.Mcp.Server.Sources;

namespace XrCopilotLab.Intrusion.Mcp.Server;

/// <summary>
/// The same answers as the MCP tools, as plain HTTP GETs under <c>/api</c>, with the same key. A blueprint can only
/// provision an MCP server it builds itself (<c>kind: builder</c>, HTTP calls on a connection): with this face the
/// whole sentinel module installs from the manifest, with no step in the UI. The MCP face stays for whoever
/// registers the server by hand. Every route takes <c>host</c>: without it, all the hosts of the key's tenant.
/// </summary>
public static class RestApi
{
    public static void MapRestApi(this WebApplication app)
    {
        var api = app.MapGroup("/api").RequireAuthorization(KeyPolicies.Query);

        api.MapGet("/hosts", (HttpContext http, QueryScope scope) => Results.Ok(new { hosts = scope.HostNames(http.User) }));

        api.MapGet("/status", (HttpContext http, QueryScope scope, TimeProvider clock, string? host, CancellationToken ct) =>
            Answer(http, scope, clock, host, ct, (q, now) => q.Status(now)));

        api.MapGet("/banned", (HttpContext http, QueryScope scope, TimeProvider clock, string? host, string? jail, CancellationToken ct) =>
            Answer(http, scope, clock, host, ct, (q, now) => q.Banned(now, Blank(jail))));

        api.MapGet("/attempts", (HttpContext http, QueryScope scope, TimeProvider clock, string? host, int? hours, DateTimeOffset? since, DateTimeOffset? until,
                int? slotMinutes, string? jail, string? attackType, string? country, int? top, CancellationToken ct) =>
            Answer(http, scope, clock, host, ct, (q, now) =>
                q.Attempts(now, q.Resolve(now, hours, since, until, slotMinutes), Blank(jail), Blank(attackType), Blank(country), top ?? 20)));

        api.MapGet("/ips/{ip}", (HttpContext http, QueryScope scope, TimeProvider clock, string ip, string? host, int? hours, DateTimeOffset? since,
                DateTimeOffset? until, CancellationToken ct) =>
            Answer(http, scope, clock, host, ct, (q, now) => q.IpDetail(now, q.Resolve(now, hours, since, until), ip.Trim())));

        api.MapGet("/suspicious-logins", (HttpContext http, QueryScope scope, TimeProvider clock, string? host, int? hours, DateTimeOffset? since,
                DateTimeOffset? until, int? slotMinutes, CancellationToken ct) =>
            Answer(http, scope, clock, host, ct, (q, now) => q.SuspiciousLogins(now, q.Resolve(now, hours, since, until, slotMinutes))));

        api.MapGet("/summary", (HttpContext http, QueryScope scope, TimeProvider clock, string? host, int? hours, DateTimeOffset? since,
                DateTimeOffset? until, int? slotMinutes, int? top, CancellationToken ct) =>
            Answer(http, scope, clock, host, ct, (q, now) => q.Summary(now, q.Resolve(now, hours, since, until, slotMinutes), top ?? 10)));
    }

    private static async Task<IResult> Answer<T>(HttpContext http, QueryScope scope, TimeProvider clock, string? host, CancellationToken ct,
        Func<IntrusionQueries, DateTimeOffset, T> answer)
    {
        var now = clock.GetUtcNow();
        var queries = await scope.OpenAsync(http.User, Blank(host), now, ct);
        return queries is null
            ? Results.NotFound(new { error = $"host '{host}' is not one of this key's hosts", hosts = scope.HostNames(http.User) })
            : Results.Ok(answer(queries, now));
    }

    // A builder tool sends an empty value for an argument the model left out: treat it as no filter.
    private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
