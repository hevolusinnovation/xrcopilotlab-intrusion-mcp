using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using XrCopilotLab.Intrusion.Mcp.Core.Models;

namespace XrCopilotLab.Intrusion.Mcp.Core.Parsing;

/// <summary>
/// Lines of the nginx access log in the default <c>combined</c> format:
/// <code>
/// 198.51.100.150 - - [10/Nov/2026:03:12:45 +0100] "GET /.env HTTP/1.1" 404 162 "-" "Mozilla/5.0 zgrab/0.x"
/// </code>
/// Only the requests that match a <see cref="WebProbeRules"/> pattern become events: ordinary traffic is skipped, so
/// a busy site does not fill the memory. The path is the attacker's text: cleaned and cut at 200 characters
/// (<see cref="UntrustedText"/>), and checked, with the user agent, for text written for an AI.
/// </summary>
public static partial class NginxAccessLogParser
{
    [GeneratedRegex(
        @"^(?<ip>[0-9A-Fa-f:.]+) \S+ \S+ \[(?<ts>[^\]]+)\] ""(?<method>[A-Z]{3,10}) (?<path>\S+)(?: HTTP/[\d.]+)?"" (?<status>\d{3}) \S+(?: ""[^""]*"" ""(?<ua>[^""]*)"")?",
        RegexOptions.CultureInvariant)]
    private static partial Regex LineRegex();

    [GeneratedRegex(@"([+-]\d{2})(\d{2})$", RegexOptions.CultureInvariant)]
    private static partial Regex OffsetRegex();

    public static bool TryParse(string line, out LogEvent? parsed)
    {
        parsed = null;
        var m = LineRegex().Match(line);
        if (!m.Success || !IPAddress.TryParse(m.Groups["ip"].Value, out var ip)) return false;
        // nginx writes the offset as +0100; .NET's zzz wants +01:00.
        var ts = OffsetRegex().Replace(m.Groups["ts"].Value, "$1:$2");
        if (!DateTimeOffset.TryParseExact(ts, "dd/MMM/yyyy:HH:mm:ss zzz", CultureInfo.InvariantCulture, DateTimeStyles.None, out var time))
            return false;

        var path = m.Groups["path"].Value;
        var status = int.Parse(m.Groups["status"].Value, CultureInfo.InvariantCulture);
        var ua = m.Groups["ua"].Success ? m.Groups["ua"].Value : null;
        if (WebProbeRules.Match(path, status, ua) is not { } match) return false;

        parsed = new LogEvent(time, LogEventKind.WebRequest, LogOrigin.WebAccess, ip.ToString(),
            Method: m.Groups["method"].Value,
            Path: UntrustedText.Clean(path, UntrustedText.MaxPath),
            Status: status,
            Rule: match.Rule,
            // The user agent is kept (cleaned) only when it is where the attacker wrote for the AI: it is the evidence.
            Detail: UntrustedText.Injection(UntrustedText.Decode(path)) is null && UntrustedText.Injection(ua) is not null
                ? UntrustedText.Clean(ua, UntrustedText.MaxPath)
                : null,
            Injection: WebProbeRules.Injection(path, ua));
        return true;
    }
}
