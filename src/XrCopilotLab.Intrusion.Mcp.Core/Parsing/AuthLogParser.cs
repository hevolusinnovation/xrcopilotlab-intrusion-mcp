using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using XrCopilotLab.Intrusion.Mcp.Core.Models;

namespace XrCopilotLab.Intrusion.Mcp.Core.Parsing;

/// <summary>
/// sshd lines of <c>/var/log/auth.log</c>, in both timestamp formats Ubuntu writes (<see cref="SyslogLine"/>):
/// <code>
/// 2026-11-10T03:12:45.123456+01:00 bastion-01 sshd[2345]: Failed password for invalid user admin from 203.0.113.7 port 51234 ssh2
/// Nov 10 03:12:45 bastion-01 sshd[2345]: Accepted publickey for deploy from 198.51.100.10 port 50122 ssh2: ED25519 SHA256:…
/// </code>
/// OpenSSH 9.8+ logs as <c>sshd-session</c>; both names are read.
/// </summary>
public static partial class AuthLogParser
{
    [GeneratedRegex(@"^Failed (?<method>password|publickey|keyboard-interactive/pam|none) for (?<invalid>invalid user )?(?<user>\S*) from (?<ip>[0-9A-Fa-f:.]+) port (?<port>\d+)", RegexOptions.CultureInvariant)]
    private static partial Regex FailedRegex();

    [GeneratedRegex(@"^Invalid user (?<user>\S*) from (?<ip>[0-9A-Fa-f:.]+)(?: port (?<port>\d+))?", RegexOptions.CultureInvariant)]
    private static partial Regex InvalidUserRegex();

    [GeneratedRegex(@"^Accepted (?<method>password|publickey|keyboard-interactive/pam) for (?<user>\S+) from (?<ip>[0-9A-Fa-f:.]+) port (?<port>\d+)", RegexOptions.CultureInvariant)]
    private static partial Regex AcceptedRegex();

    public static bool TryParse(string line, TimeZoneInfo zone, DateTimeOffset now, out LogEvent? parsed)
    {
        parsed = null;
        if (!SyslogLine.TryParse(line, zone, now, out var time, out var program, out var msg)) return false;
        if (program is not ("sshd" or "sshd-session")) return false;

        var f = FailedRegex().Match(msg);
        if (f.Success)
            return Build(time, LogEventKind.FailedLogin, f, f.Groups["method"].Value, out parsed);

        var i = InvalidUserRegex().Match(msg);
        if (i.Success)
            return Build(time, LogEventKind.InvalidUser, i, null, out parsed);

        var a = AcceptedRegex().Match(msg);
        if (a.Success)
            return Build(time, LogEventKind.AcceptedLogin, a, a.Groups["method"].Value, out parsed);

        return false;
    }

    private static bool Build(DateTimeOffset time, LogEventKind kind, Match m, string? method, out LogEvent? parsed)
    {
        parsed = null;
        if (!IPAddress.TryParse(m.Groups["ip"].Value, out var ip)) return false;
        int? port = int.TryParse(m.Groups["port"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var p) ? p : null;
        var user = m.Groups["user"].Value;
        parsed = new LogEvent(time, kind, LogOrigin.Auth, ip.ToString(), Jail: null, User: user.Length == 0 ? null : user, Port: port, Method: method);
        return true;
    }
}
