using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using XrCopilotLab.Intrusion.Mcp.Core.Models;

namespace XrCopilotLab.Intrusion.Mcp.Core.Parsing;

/// <summary>
/// Lines of <c>/var/log/ufw.log</c> (UFW with <c>ufw logging low</c> or higher):
/// <code>
/// 2026-11-10T00:31:02.118204+01:00 bastion-01 kernel: [812345.123456] [UFW BLOCK] IN=eth0 OUT= MAC=… SRC=198.51.100.213 DST=10.30.0.15 LEN=44 … PROTO=TCP SPT=40112 DPT=3389 WINDOW=1024 RES=0x00 SYN URGP=0
/// </code>
/// Only <c>[UFW BLOCK]</c> lines are kept: <c>ALLOW</c> and <c>AUDIT</c> say nothing about an attack.
/// </summary>
public static partial class UfwLogParser
{
    [GeneratedRegex(@"\[UFW BLOCK\].*?\bSRC=(?<src>[0-9A-Fa-f:.]+).*?\bPROTO=(?<proto>\w+)(?:.*?\bDPT=(?<dpt>\d+))?", RegexOptions.CultureInvariant)]
    private static partial Regex BlockRegex();

    public static bool TryParse(string line, TimeZoneInfo zone, DateTimeOffset now, out LogEvent? parsed)
    {
        parsed = null;
        if (!SyslogLine.TryParse(line, zone, now, out var time, out var program, out var msg) || program != "kernel") return false;
        var m = BlockRegex().Match(msg);
        if (!m.Success || !IPAddress.TryParse(m.Groups["src"].Value, out var ip)) return false;

        int? port = m.Groups["dpt"].Success && int.TryParse(m.Groups["dpt"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var p) ? p : null;
        parsed = new LogEvent(time, LogEventKind.FirewallBlock, LogOrigin.Firewall, ip.ToString(), TargetPort: port, Protocol: m.Groups["proto"].Value);
        return true;
    }
}
