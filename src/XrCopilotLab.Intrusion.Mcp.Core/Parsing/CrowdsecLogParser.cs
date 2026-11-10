using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using XrCopilotLab.Intrusion.Mcp.Core.Models;

namespace XrCopilotLab.Intrusion.Mcp.Core.Parsing;

/// <summary>
/// The two lines of <c>/var/log/crowdsec.log</c> about an address:
/// <code>
/// time="2026-11-10T01:25:13+01:00" level=info msg="Ip 198.51.100.213 performed 'crowdsecurity/ssh-slow-bf' (11 events over 31m2s) at 2026-11-10 00:25:13.48 +0000 UTC"
/// time="2026-11-10T01:25:13+01:00" level=info msg="(5ac0d2f1e8a94c4a/crowdsec) crowdsecurity/ssh-slow-bf by ip 198.51.100.213 (MD/64499) : 4h ban on Ip 198.51.100.213"
/// </code>
/// The first is the alert (a scenario recognised), the second the decision. Whether the decision is enforced depends on
/// a bouncer, which this log does not show.
/// </summary>
public static partial class CrowdsecLogParser
{
    [GeneratedRegex(@"^time=""(?<ts>[^""]+)""\s+level=\w+\s+msg=""(?<msg>.*)""\s*$", RegexOptions.CultureInvariant)]
    private static partial Regex LineRegex();

    [GeneratedRegex(@"^Ip (?<ip>[0-9A-Fa-f:.]+) performed '(?<scenario>[^']+)' \((?<events>\d+) events over (?<over>[^)]+)\)", RegexOptions.CultureInvariant)]
    private static partial Regex AlertRegex();

    [GeneratedRegex(@"\) (?<scenario>\S+) by ip (?<ip>[0-9A-Fa-f:.]+)(?: \([^)]*\))? : (?<duration>\S+) (?<type>\w+) on Ip ", RegexOptions.CultureInvariant)]
    private static partial Regex DecisionRegex();

    public static bool TryParse(string line, out LogEvent? parsed)
    {
        parsed = null;
        var m = LineRegex().Match(line);
        if (!m.Success || !DateTimeOffset.TryParse(m.Groups["ts"].Value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var time)) return false;
        var msg = m.Groups["msg"].Value;

        var a = AlertRegex().Match(msg);
        if (a.Success && IPAddress.TryParse(a.Groups["ip"].Value, out var ip))
        {
            parsed = new LogEvent(time, LogEventKind.CrowdsecAlert, LogOrigin.Crowdsec, ip.ToString(),
                Rule: a.Groups["scenario"].Value, Detail: $"{a.Groups["events"].Value} events over {a.Groups["over"].Value}");
            return true;
        }

        var d = DecisionRegex().Match(msg);
        if (d.Success && IPAddress.TryParse(d.Groups["ip"].Value, out var dip))
        {
            parsed = new LogEvent(time, LogEventKind.CrowdsecDecision, LogOrigin.Crowdsec, dip.ToString(),
                Rule: d.Groups["scenario"].Value, Detail: $"{d.Groups["duration"].Value} {d.Groups["type"].Value}");
            return true;
        }
        return false;
    }
}
