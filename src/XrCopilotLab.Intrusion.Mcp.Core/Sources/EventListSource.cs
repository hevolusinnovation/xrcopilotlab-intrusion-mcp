using XrCopilotLab.Intrusion.Mcp.Core.Models;

namespace XrCopilotLab.Intrusion.Mcp.Core.Sources;

/// <summary>
/// A host whose events are already in memory, sorted by time: what the collector loaded from its store for one call.
/// </summary>
public sealed class EventListSource(HostInfo host, int maxDays, IReadOnlyList<string> describe, IReadOnlyList<LogEvent> sortedEvents) : ILogSource
{
    public string Hostname => host.Name;

    public bool Simulated => host.Simulated;

    public int MaxDays => maxDays;

    public IReadOnlyList<HostInfo> Hosts => [host];

    public IReadOnlyList<string> Describe() => describe;

    public IReadOnlyList<LogEvent> Read(DateTimeOffset since, DateTimeOffset now)
    {
        var start = LowerBound(since);
        var result = new List<LogEvent>();
        for (var i = start; i < sortedEvents.Count && sortedEvents[i].Time <= now; i++) result.Add(sortedEvents[i]);
        return result;
    }

    private int LowerBound(DateTimeOffset since)
    {
        int lo = 0, hi = sortedEvents.Count;
        while (lo < hi)
        {
            var mid = (lo + hi) / 2;
            if (sortedEvents[mid].Time < since) lo = mid + 1;
            else hi = mid;
        }
        return lo;
    }
}
