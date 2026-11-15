using XrCopilotLab.Intrusion.Mcp.Core.Sources;

namespace XrCopilotLab.Intrusion.Mcp.Core.Collector;

/// <summary>
/// What an agent sends to <c>POST /ingest</c>: new lines of its logs. The host is not in the body: it is the one
/// the key was issued for, so a host cannot write in the name of another.
/// </summary>
public sealed record IngestRequest(string? Agent, string? TimeZone, IReadOnlyList<IngestLog>? Logs);

/// <summary>Lines of one log (<see cref="LogNames"/>).</summary>
public sealed record IngestLog(string Log, IReadOnlyList<string> Lines);

public sealed record IngestResult(int Received, int Stored, DateTimeOffset At);

public static class IngestRules
{
    public const int MaxLines = 20_000;
    public const int MaxLineLength = 8_192;

    /// <summary>Null when the request can be stored, otherwise why not.</summary>
    public static string? Validate(IngestRequest? request)
    {
        if (request?.Logs is null || request.Logs.Count == 0) return "no logs in the request";
        var total = 0;
        foreach (var log in request.Logs)
        {
            if (!LogNames.IsKnown(log?.Log)) return $"unknown log '{log?.Log}': expected one of {string.Join(", ", LogNames.All)}";
            if (log!.Lines is null) return $"log '{log.Log}' has no lines";
            total += log.Lines.Count;
            if (log.Lines.Any(l => l is null || l.Length > MaxLineLength)) return $"a line of '{log.Log}' is empty or longer than {MaxLineLength} characters";
        }
        return total > MaxLines ? $"{total} lines: at most {MaxLines} per request" : null;
    }

    /// <summary>The host's zone, or UTC when the agent sent none or one this system does not know.</summary>
    public static TimeZoneInfo Zone(string? id)
    {
        if (string.IsNullOrWhiteSpace(id)) return TimeZoneInfo.Utc;
        try { return TimeZoneInfo.FindSystemTimeZoneById(id); }
        catch (TimeZoneNotFoundException) { return TimeZoneInfo.Utc; }
        catch (InvalidTimeZoneException) { return TimeZoneInfo.Utc; }
    }
}
