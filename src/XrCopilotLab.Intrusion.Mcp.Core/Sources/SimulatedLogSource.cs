using System.Collections.Concurrent;
using XrCopilotLab.Intrusion.Mcp.Core.Models;
using XrCopilotLab.Intrusion.Mcp.Core.Simulation;

namespace XrCopilotLab.Intrusion.Mcp.Core.Sources;

/// <summary>
/// The simulated host as a log source: each day's lines are generated, then parsed by the same parsers that read a
/// real host. A past day never changes, so it is generated once; today is cut at <c>now</c>, so new attacks appear
/// as the day goes on, as on a real host.
/// </summary>
public sealed class SimulatedLogSource(SimulationOptions options) : ILogSource
{
    private readonly SyntheticHost _host = new(options);
    private readonly TimeZoneInfo _zone = TimeZoneInfo.FindSystemTimeZoneById(options.TimeZone);
    private readonly ConcurrentDictionary<DateOnly, IReadOnlyList<LogEvent>> _days = new();

    public string Hostname => options.Hostname;

    public bool Simulated => true;

    public int MaxDays => options.Days;

    public IReadOnlyList<string> Describe() =>
        [$"simulated host {options.Hostname}: /var/log/fail2ban.log and /var/log/auth.log, {options.Days} days, seed {options.Seed}"];

    public IReadOnlyList<LogEvent> Read(DateTimeOffset since, DateTimeOffset now)
    {
        var floor = now.AddDays(-options.Days);
        if (since < floor) since = floor;

        // Events of a day can spill over midnight (a ban lasts an hour, recidive a week): start a week earlier.
        var first = DateOnly.FromDateTime(TimeZoneInfo.ConvertTime(since, _zone).DateTime).AddDays(-7);
        var last = DateOnly.FromDateTime(TimeZoneInfo.ConvertTime(now, _zone).DateTime);
        if (_days.Count > options.Days + 16) _days.Clear();

        var events = new List<LogEvent>();
        for (var d = first; d <= last; d = d.AddDays(1))
            foreach (var e in _days.GetOrAdd(d, Day))
                if (e.Time >= since && e.Time <= now) events.Add(e);

        events.Sort((a, b) => a.Time.CompareTo(b.Time));
        return events;
    }

    private IReadOnlyList<LogEvent> Day(DateOnly day)
    {
        var lines = _host.Generate(day);
        return LogLines.Parse(lines.Fail2banLines, lines.AuthLines, _zone, DateTimeOffset.MaxValue).ToList();
    }
}
