using Microsoft.Extensions.Options;
using XrCopilotLab.Intrusion.Mcp.Core.Collector;
using XrCopilotLab.Intrusion.Mcp.Core.Sources;
using XrCopilotLab.Intrusion.Mcp.Server.Collector;

namespace XrCopilotLab.Intrusion.Mcp.Server.Sources;

/// <summary>
/// The source a call reads: for a tenant (from the key) and an optional host. Without a host, all the tenant's hosts
/// together. Null when the host is not one of the tenant's.
/// </summary>
public interface ISourceResolver
{
    Task<ILogSource?> ResolveAsync(string tenant, string? host, DateTimeOffset now, CancellationToken ct);

    IReadOnlyList<string> HostNames(string tenant);
}

/// <summary>The <c>logs</c> and <c>simulated</c> modes: one host, whatever the tenant of the key.</summary>
public sealed class SingleSourceResolver(ILogSource source) : ISourceResolver
{
    public Task<ILogSource?> ResolveAsync(string tenant, string? host, DateTimeOffset now, CancellationToken ct) =>
        Task.FromResult(host is null || string.Equals(host, source.Hostname, StringComparison.OrdinalIgnoreCase) ? source : null);

    public IReadOnlyList<string> HostNames(string tenant) => [source.Hostname];
}

/// <summary>
/// The collector: the hosts registered for the tenant, read from the store, plus the simulated host for the tenants
/// that have it. A host keeps its history after its key is revoked.
/// </summary>
public sealed class CollectorSourceResolver(IOptionsMonitor<CollectorOptions> options, StoredEvents stored, SimulatedLogSource? simulated) : ISourceResolver
{
    public IReadOnlyList<string> HostNames(string tenant)
    {
        var names = new List<string>();
        if (HasSimulated(tenant)) names.Add(simulated!.Hostname);
        names.AddRange(options.CurrentValue.Hosts
            .Where(h => string.Equals(h.Tenant, tenant, StringComparison.Ordinal) && !string.IsNullOrWhiteSpace(h.Name))
            .Select(h => h.Name)
            .Distinct(StringComparer.Ordinal));
        return names;
    }

    public async Task<ILogSource?> ResolveAsync(string tenant, string? host, DateTimeOffset now, CancellationToken ct)
    {
        var names = HostNames(tenant);
        if (host is not null)
        {
            var name = names.FirstOrDefault(n => string.Equals(n, host, StringComparison.OrdinalIgnoreCase));
            return name is null ? null : await OpenAsync(tenant, name, now, ct);
        }
        if (names.Count == 0) return null;

        var sources = new List<ILogSource>();
        foreach (var name in names) sources.Add(await OpenAsync(tenant, name, now, ct));
        return sources.Count == 1 ? sources[0] : new MergedLogSource(sources);
    }

    private bool HasSimulated(string tenant) =>
        simulated is not null && options.CurrentValue.SimulatedTenants.Contains(tenant, StringComparer.Ordinal);

    private async Task<ILogSource> OpenAsync(string tenant, string name, DateTimeOffset now, CancellationToken ct)
    {
        if (HasSimulated(tenant) && name == simulated!.Hostname) return simulated;
        var (events, last) = await stored.LoadAsync(tenant, name, now, ct);
        var described = last is null ? $"{name}: agent registered, nothing received yet" : $"{name}: agent, last lines received {last:yyyy-MM-ddTHH:mm:ssZ}";
        return new EventListSource(new HostInfo(name, false, last), stored.RetentionDays, [described], events);
    }
}
