using XrCopilotLab.Intrusion.Mcp.Core.Models;

namespace XrCopilotLab.Intrusion.Mcp.Core.Sources;

/// <summary>
/// One host a source covers. <see cref="LastReceived"/> is when its agent last sent lines to the collector: null for a
/// host read in place (its own files, or the simulated host), where the question does not arise.
/// </summary>
public sealed record HostInfo(string Name, bool Simulated, DateTimeOffset? LastReceived = null);

/// <summary>Where the events come from: the host's log files, the simulated host, or what agents sent to the collector.</summary>
public interface ILogSource
{
    string Hostname { get; }

    bool Simulated { get; }

    /// <summary>How far back the source can go.</summary>
    int MaxDays { get; }

    /// <summary>The hosts behind this source: one, unless it merges the hosts of a tenant.</summary>
    IReadOnlyList<HostInfo> Hosts => [new HostInfo(Hostname, Simulated)];

    /// <summary>What is being read, for the status tool (file paths, or "simulated").</summary>
    IReadOnlyList<string> Describe();

    /// <summary>The events with <see cref="LogEvent.Time"/> in [<paramref name="since"/>, <paramref name="now"/>], oldest first.</summary>
    IReadOnlyList<LogEvent> Read(DateTimeOffset since, DateTimeOffset now);
}
