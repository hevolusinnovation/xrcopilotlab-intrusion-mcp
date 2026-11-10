using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using XrCopilotLab.Intrusion.Mcp.Core.Models;

namespace XrCopilotLab.Intrusion.Mcp.Core.Parsing;

/// <summary>
/// Lines of <c>/var/log/fail2ban.log</c>:
/// <code>
/// 2026-11-10 03:12:45,123 fail2ban.filter         [812]: INFO    [sshd] Found 203.0.113.7 - 2026-11-10 03:12:45
/// 2026-11-10 03:12:46,004 fail2ban.actions        [812]: NOTICE  [sshd] Ban 203.0.113.7
/// 2026-11-10 04:12:46,010 fail2ban.actions        [812]: NOTICE  [sshd] Unban 203.0.113.7
/// 2026-11-10 08:00:01,377 fail2ban.actions        [812]: NOTICE  [sshd] Restore Ban 203.0.113.7
/// </code>
/// Every other line (startup, "already banned", jail statistics) is ignored.
/// </summary>
public static partial class Fail2banLogParser
{
    [GeneratedRegex(
        @"^(?<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:,\d+)?\s+fail2ban\.\w+\s+\[\d+\]:\s+\w+\s+\[(?<jail>[^\]]+)\]\s+(?<action>Found|Restore Ban|Ban|Unban)\s+(?<ip>[0-9A-Fa-f:.]+)",
        RegexOptions.CultureInvariant)]
    private static partial Regex LineRegex();

    public static bool TryParse(string line, TimeZoneInfo zone, out LogEvent? parsed)
    {
        parsed = null;
        var m = LineRegex().Match(line);
        if (!m.Success || !IPAddress.TryParse(m.Groups["ip"].Value, out var ip)) return false;
        if (!DateTime.TryParseExact(m.Groups["ts"].Value, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out var local))
            return false;

        var kind = m.Groups["action"].Value switch
        {
            "Found" => LogEventKind.Found,
            "Ban" => LogEventKind.Ban,
            "Unban" => LogEventKind.Unban,
            _ => LogEventKind.RestoreBan,
        };
        parsed = new LogEvent(LocalTime.ToOffset(local, zone), kind, LogOrigin.Fail2ban, ip.ToString(), Jail: m.Groups["jail"].Value);
        return true;
    }
}
