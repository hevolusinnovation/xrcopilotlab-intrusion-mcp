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
    IEnumerable<string>? Suricata = null,
    IEnumerable<string>? Falco = null,
    IEnumerable<string>? ModSecurity = null);

/// <summary>The names of the logs, as an agent sends them to the collector and as the collector stores them.</summary>
public static class LogNames
{
    public const string Fail2ban = "fail2ban";
    public const string Auth = "auth";
    public const string Firewall = "firewall";
    public const string WebAccess = "web";
    public const string Crowdsec = "crowdsec";
    public const string Suricata = "suricata";
    public const string Falco = "falco";
    public const string ModSecurity = "modsecurity";

    public static readonly IReadOnlyList<string> All = [Fail2ban, Auth, Firewall, WebAccess, Crowdsec, Suricata, Falco, ModSecurity];

    public static bool IsKnown(string? name) => name is not null && All.Contains(name, StringComparer.Ordinal);
}

/// <summary>Turns the lines of the logs into events. Lines that say nothing about a source IP are skipped, except
/// Falco's, which are about the host itself.</summary>
public static class LogLines
{
    /// <param name="local">The host's own addresses, to tell a Suricata alert coming in from a connection going out.</param>
    public static IEnumerable<LogEvent> Parse(LogSet logs, TimeZoneInfo zone, DateTimeOffset now, IReadOnlySet<string>? local = null)
    {
        foreach (var e in Parse(LogNames.Fail2ban, logs.Fail2ban, zone, now, local)) yield return e;
        foreach (var e in Parse(LogNames.Auth, logs.Auth, zone, now, local)) yield return e;
        foreach (var e in Parse(LogNames.Firewall, logs.Firewall, zone, now, local)) yield return e;
        foreach (var e in Parse(LogNames.WebAccess, logs.WebAccess, zone, now, local)) yield return e;
        foreach (var e in Parse(LogNames.Crowdsec, logs.Crowdsec, zone, now, local)) yield return e;
        foreach (var e in Parse(LogNames.Suricata, logs.Suricata ?? [], zone, now, local)) yield return e;
        foreach (var e in Parse(LogNames.Falco, logs.Falco ?? [], zone, now, local)) yield return e;
        foreach (var e in Parse(LogNames.ModSecurity, logs.ModSecurity ?? [], zone, now, local)) yield return e;
    }

    public static IEnumerable<LogEvent> Parse(string log, IEnumerable<string> lines, TimeZoneInfo zone, DateTimeOffset now, IReadOnlySet<string>? local = null)
    {
        foreach (var line in lines)
            if (TryParse(log, line, zone, now, out var e, local)) yield return e!;
    }

    /// <summary>
    /// One line of the named log. <paramref name="now"/> is when the line was read: syslog lines without a year take the
    /// year that puts them at or before it. <paramref name="local"/>: the host's own addresses, for Suricata; without
    /// them (the collector does not know them) every alert counts as coming in.
    /// </summary>
    public static bool TryParse(string log, string line, TimeZoneInfo zone, DateTimeOffset now, out LogEvent? e, IReadOnlySet<string>? local = null)
    {
        switch (log)
        {
            case LogNames.Fail2ban: return Fail2banLogParser.TryParse(line, zone, out e);
            case LogNames.Auth: return AuthLogParser.TryParse(line, zone, now, out e);
            case LogNames.Firewall: return UfwLogParser.TryParse(line, zone, now, out e);
            case LogNames.WebAccess: return NginxAccessLogParser.TryParse(line, out e);
            case LogNames.Crowdsec: return CrowdsecLogParser.TryParse(line, out e);
            case LogNames.Suricata: return SuricataEveParser.TryParse(line, local ?? NoAddresses, out e);
            case LogNames.Falco: return FalcoParser.TryParse(line, out e);
            case LogNames.ModSecurity: return ModSecurityParser.TryParse(line, zone, out e);
            default:
                e = null;
                return false;
        }
    }

    private static readonly IReadOnlySet<string> NoAddresses = new HashSet<string>();
}
