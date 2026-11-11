using XrCopilotLab.Intrusion.Mcp.Core.Models;
using XrCopilotLab.Intrusion.Mcp.Core.Parsing;

namespace XrCopilotLab.Intrusion.Mcp.Core.Sources;

/// <summary>The lines of the five logs the server understands. A log the host does not have is simply empty.</summary>
public sealed record LogSet(
    IEnumerable<string> Fail2ban,
    IEnumerable<string> Auth,
    IEnumerable<string> Firewall,
    IEnumerable<string> WebAccess,
    IEnumerable<string> Crowdsec);

/// <summary>The names of the logs, as an agent sends them to the collector and as the collector stores them.</summary>
public static class LogNames
{
    public const string Fail2ban = "fail2ban";
    public const string Auth = "auth";
    public const string Firewall = "firewall";
    public const string WebAccess = "web";
    public const string Crowdsec = "crowdsec";

    public static readonly IReadOnlyList<string> All = [Fail2ban, Auth, Firewall, WebAccess, Crowdsec];

    public static bool IsKnown(string? name) => name is not null && All.Contains(name, StringComparer.Ordinal);
}

/// <summary>Turns the lines of the logs into events. Lines that say nothing about a source IP are skipped.</summary>
public static class LogLines
{
    public static IEnumerable<LogEvent> Parse(LogSet logs, TimeZoneInfo zone, DateTimeOffset now)
    {
        foreach (var e in Parse(LogNames.Fail2ban, logs.Fail2ban, zone, now)) yield return e;
        foreach (var e in Parse(LogNames.Auth, logs.Auth, zone, now)) yield return e;
        foreach (var e in Parse(LogNames.Firewall, logs.Firewall, zone, now)) yield return e;
        foreach (var e in Parse(LogNames.WebAccess, logs.WebAccess, zone, now)) yield return e;
        foreach (var e in Parse(LogNames.Crowdsec, logs.Crowdsec, zone, now)) yield return e;
    }

    public static IEnumerable<LogEvent> Parse(string log, IEnumerable<string> lines, TimeZoneInfo zone, DateTimeOffset now)
    {
        foreach (var line in lines)
            if (TryParse(log, line, zone, now, out var e)) yield return e!;
    }

    /// <summary>
    /// One line of the named log. <paramref name="now"/> is when the line was read: syslog lines without a year take the
    /// year that puts them at or before it.
    /// </summary>
    public static bool TryParse(string log, string line, TimeZoneInfo zone, DateTimeOffset now, out LogEvent? e)
    {
        switch (log)
        {
            case LogNames.Fail2ban: return Fail2banLogParser.TryParse(line, zone, out e);
            case LogNames.Auth: return AuthLogParser.TryParse(line, zone, now, out e);
            case LogNames.Firewall: return UfwLogParser.TryParse(line, zone, now, out e);
            case LogNames.WebAccess: return NginxAccessLogParser.TryParse(line, out e);
            case LogNames.Crowdsec: return CrowdsecLogParser.TryParse(line, out e);
            default:
                e = null;
                return false;
        }
    }
}
