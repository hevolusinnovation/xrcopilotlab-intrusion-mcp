using System.Globalization;
using System.Text.RegularExpressions;
using XrCopilotLab.Intrusion.Mcp.Core.Sources;

namespace XrCopilotLab.Intrusion.Mcp.Core.Collector;

/// <summary>
/// <c>{tenant}/{host}/{yyyy-MM-dd}/{log}.jsonl</c>, where the day is the UTC day the collector received the lines. A
/// line is always received after it was written, so the files of the days from the start of a period onwards hold every
/// event of that period; and a day that is over never changes again.
/// </summary>
public static partial class StorePaths
{
    public const string Extension = ".jsonl";

    [GeneratedRegex("^[a-z0-9][a-z0-9._-]{0,62}$")]
    private static partial Regex NameRegex();

    /// <summary>Tenant and host names: lowercase letters, digits, <c>.</c>, <c>_</c>, <c>-</c>; they become path segments.</summary>
    public static bool IsValidName(string? name) => name is not null && NameRegex().IsMatch(name);

    public static string Prefix(string tenant, string host) => $"{tenant}/{host}/";

    public static string For(string tenant, string host, DateOnly day, string log) =>
        $"{Prefix(tenant, host)}{day.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}/{log}{Extension}";

    /// <summary>The day and the log of a path written by <see cref="For"/>; false for anything else.</summary>
    public static bool TryParse(string path, out DateOnly day, out string log)
    {
        day = default;
        log = "";
        var parts = path.Split('/');
        if (parts.Length != 4 || !parts[3].EndsWith(Extension, StringComparison.Ordinal)) return false;
        if (!DateOnly.TryParseExact(parts[2], "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out day)) return false;
        log = parts[3][..^Extension.Length];
        return LogNames.IsKnown(log);
    }
}
