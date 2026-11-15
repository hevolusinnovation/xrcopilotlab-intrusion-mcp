using System.Security.Claims;
using XrCopilotLab.Intrusion.Mcp.Core.Analysis;
using XrCopilotLab.Intrusion.Mcp.Core.Geo;
using XrCopilotLab.Intrusion.Mcp.Core.Queries;
using XrCopilotLab.Intrusion.Mcp.Server.Authentication;
using XrCopilotLab.Intrusion.Mcp.Server.Collector;

namespace XrCopilotLab.Intrusion.Mcp.Server.Sources;

/// <summary>Builds the queries of one call: the source of the caller's tenant and host, the shared geography and policy.</summary>
public sealed class QueryScope(ISourceResolver resolver, IGeoLocator geo, IntrusionPolicy policy)
{
    /// <summary>Null when the host is not one of the tenant's: the caller answers with the hosts it has.</summary>
    public async Task<IntrusionQueries?> OpenAsync(ClaimsPrincipal user, string? host, DateTimeOffset now, CancellationToken ct)
    {
        var source = await resolver.ResolveAsync(Tenant(user), host, now, ct);
        return source is null ? null : new IntrusionQueries(source, geo, policy);
    }

    public IReadOnlyList<string> HostNames(ClaimsPrincipal user) => resolver.HostNames(Tenant(user));

    public static string Tenant(ClaimsPrincipal user) => user.FindFirst(KeyClaims.Tenant)?.Value ?? TenantNames.Default;
}
