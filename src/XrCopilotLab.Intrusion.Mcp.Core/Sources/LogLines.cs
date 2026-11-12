using XrCopilotLab.Intrusion.Mcp.Core.Models;
using XrCopilotLab.Intrusion.Mcp.Core.Parsing;

namespace XrCopilotLab.Intrusion.Mcp.Core.Sources;

/// <summary>The lines of the logs the server understands. A log the host does not have is simply empty.</summary>
public sealed record LogSet(
    IEnumerable<string> Fail2ban,
    IEnumerable<string> Auth,
    IEnumerable<string> Firewall,
    IEnumerable<string> WebAccess,
    IEnumerable<string> Crowdsec,
    IEnumerable<string>? Suricata = null);

/// <summary>Turns the lines of the logs into events. Lines that say nothing about a source IP are skipped.</summary>
public static class LogLines
{
    /// <param name="local">The host's own addresses, to tell a Suricata alert coming in from a connection going out.</param>
    public static IEnumerable<LogEvent> Parse(LogSet logs, TimeZoneInfo zone, DateTimeOffset now, IReadOnlySet<string>? local = null)
    {
        foreach (var line in logs.Fail2ban)
            if (Fail2banLogParser.TryParse(line, zone, out var e)) yield return e!;
        foreach (var line in logs.Auth)
            if (AuthLogParser.TryParse(line, zone, now, out var e)) yield return e!;
        foreach (var line in logs.Firewall)
            if (UfwLogParser.TryParse(line, zone, now, out var e)) yield return e!;
        foreach (var line in logs.WebAccess)
            if (NginxAccessLogParser.TryParse(line, out var e)) yield return e!;
        foreach (var line in logs.Crowdsec)
            if (CrowdsecLogParser.TryParse(line, out var e)) yield return e!;
        foreach (var line in logs.Suricata ?? [])
            if (SuricataEveParser.TryParse(line, local ?? NoAddresses, out var e)) yield return e!;
    }

    private static readonly IReadOnlySet<string> NoAddresses = new HashSet<string>();
}
