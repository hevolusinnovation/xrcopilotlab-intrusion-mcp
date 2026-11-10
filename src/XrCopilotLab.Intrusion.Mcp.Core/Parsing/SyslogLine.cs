using System.Globalization;
using System.Text.RegularExpressions;

namespace XrCopilotLab.Intrusion.Mcp.Core.Parsing;

/// <summary>
/// The prefix rsyslog writes on Ubuntu, in both formats:
/// <code>
/// 2026-11-10T03:12:45.123456+01:00 bastion-01 sshd[2345]: message
/// Nov 10 03:12:45 bastion-01 kernel: message
/// </code>
/// The classic format has no year and no offset: the year is the one that puts the line in the past, the offset is
/// the host's zone.
/// </summary>
internal static partial class SyslogLine
{
    [GeneratedRegex(
        @"^(?:(?<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))|(?<classic>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}))\s+\S+\s+(?<program>[\w.-]+)(?:\[\d+\])?:\s+(?<msg>.*)$",
        RegexOptions.CultureInvariant)]
    private static partial Regex PrefixRegex();

    public static bool TryParse(string line, TimeZoneInfo zone, DateTimeOffset now, out DateTimeOffset time, out string program, out string message)
    {
        time = default;
        program = message = "";
        var m = PrefixRegex().Match(line);
        if (!m.Success || !TryTime(m, zone, now, out time)) return false;
        program = m.Groups["program"].Value;
        message = m.Groups["msg"].Value;
        return true;
    }

    private static bool TryTime(Match m, TimeZoneInfo zone, DateTimeOffset now, out DateTimeOffset time)
    {
        if (m.Groups["iso"].Success)
            return DateTimeOffset.TryParse(m.Groups["iso"].Value, CultureInfo.InvariantCulture, DateTimeStyles.None, out time);

        time = default;
        // "Nov  9 03:12:45": the day is padded with a space.
        var classic = m.Groups["classic"].Value.Replace("  ", " ", StringComparison.Ordinal);
        var localNow = TimeZoneInfo.ConvertTime(now, zone);
        if (!DateTime.TryParseExact($"{localNow.Year} {classic}", "yyyy MMM d HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out var local))
            return false;
        // A December line read in January belongs to last year.
        if (local > localNow.DateTime.AddDays(1)) local = local.AddYears(-1);
        time = LocalTime.ToOffset(local, zone);
        return true;
    }
}
