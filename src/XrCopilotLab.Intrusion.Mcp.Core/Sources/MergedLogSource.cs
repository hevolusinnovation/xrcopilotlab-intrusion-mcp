using XrCopilotLab.Intrusion.Mcp.Core.Models;

namespace XrCopilotLab.Intrusion.Mcp.Core.Sources;

/// <summary>
/// The hosts of a tenant seen as one: what the agent gets when it does not name a host. Every event keeps its
/// <see cref="LogEvent.Host"/>, so a timeline still says where each line comes from. Simulated only if every host is.
/// </summary>
public sealed class MergedLogSource(IReadOnlyList<ILogSource> sources) : ILogSource
{
    public string Hostname => string.Join(", ", sources.Select(s => s.Hostname));

    public bool Simulated => sources.Count > 0 && sources.All(s => s.Simulated);

    public int MaxDays => sources.Count == 0 ? 1 : sources.Max(s => s.MaxDays);

    public IReadOnlyList<HostInfo> Hosts => sources.SelectMany(s => s.Hosts).ToList();

    public IReadOnlyList<string> Describe() => sources.SelectMany(s => s.Describe()).ToList();

    public IReadOnlyList<LogEvent> Read(DateTimeOffset since, DateTimeOffset now)
    {
        var events = sources.SelectMany(s => s.Read(since, now)).ToList();
        events.Sort((a, b) => a.Time.CompareTo(b.Time));
        return events;
    }
}
