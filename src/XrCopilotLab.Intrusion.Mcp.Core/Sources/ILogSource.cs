using XrCopilotLab.Intrusion.Mcp.Core.Models;

namespace XrCopilotLab.Intrusion.Mcp.Core.Sources;

/// <summary>Where the events come from: the host's log files, or the simulated host.</summary>
public interface ILogSource
{
    string Hostname { get; }

    bool Simulated { get; }

    /// <summary>How far back the source can go.</summary>
    int MaxDays { get; }

    /// <summary>What is being read, for the status tool (file paths, or "simulated").</summary>
    IReadOnlyList<string> Describe();

    /// <summary>The events with <see cref="LogEvent.Time"/> in [<paramref name="since"/>, <paramref name="now"/>], oldest first.</summary>
    IReadOnlyList<LogEvent> Read(DateTimeOffset since, DateTimeOffset now);
}
