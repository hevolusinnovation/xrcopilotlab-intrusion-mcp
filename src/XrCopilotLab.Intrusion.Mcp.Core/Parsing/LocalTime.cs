namespace XrCopilotLab.Intrusion.Mcp.Core.Parsing;

/// <summary>fail2ban and the classic syslog format write the host's local time without an offset.</summary>
internal static class LocalTime
{
    public static DateTimeOffset ToOffset(DateTime local, TimeZoneInfo zone)
    {
        var unspecified = DateTime.SpecifyKind(local, DateTimeKind.Unspecified);
        // A time in the spring-forward gap does not exist: the clock had already moved on.
        if (zone.IsInvalidTime(unspecified)) unspecified = unspecified.AddHours(1);
        return new DateTimeOffset(unspecified, zone.GetUtcOffset(unspecified));
    }
}
