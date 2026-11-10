using XrCopilotLab.Intrusion.Mcp.Core.Models;
using XrCopilotLab.Intrusion.Mcp.Core.Parsing;

namespace XrCopilotLab.Intrusion.Mcp.Core.Sources;

/// <summary>Turns the lines of the two logs into events. Lines that say nothing about a source IP are skipped.</summary>
public static class LogLines
{
    public static IEnumerable<LogEvent> Parse(IEnumerable<string> fail2banLines, IEnumerable<string> authLines, TimeZoneInfo zone, DateTimeOffset now)
    {
        foreach (var line in fail2banLines)
            if (Fail2banLogParser.TryParse(line, zone, out var e)) yield return e!;
        foreach (var line in authLines)
            if (AuthLogParser.TryParse(line, zone, now, out var e)) yield return e!;
    }
}
