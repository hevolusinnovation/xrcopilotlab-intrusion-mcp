namespace XrCopilotLab.Intrusion.Mcp.Core.Advice;

/// <summary>
/// The hardening advice a person approved in the SOC process and sent back to the toolkit. The toolkit only shows it
/// (on the monitoring page and to the agent) and NEVER applies it or runs the command: it never changes anything on
/// the host on its own. The customer applies a recommendation by hand.
/// </summary>

/// <summary>What <c>POST /api/advice</c> accepts. Every field is text chosen upstream: treat it as data, escape it
/// when shown, never run it. <c>Id</c> is the idempotency key (the process instance id): the same id updates, never
/// duplicates.</summary>
public sealed record AdviceRequest(
    string? Id,
    string? FindingId,
    string? Ip,
    string? Severity,
    string? Title,
    string? Recommendation,
    string? Command,
    string? ApprovedBy,
    DateTimeOffset? ApprovedAt,
    string? Source);

/// <summary>One stored piece of advice. <c>Status</c> is <c>received</c> or <c>done</c>. <c>ReceivedAt</c> is when the
/// toolkit got it; <c>DoneAt</c> when an operator marked it done on the page.</summary>
public sealed record AdviceItem(
    string Id,
    string? FindingId,
    string? Ip,
    string Severity,
    string Title,
    string Recommendation,
    string? Command,
    string ApprovedBy,
    DateTimeOffset ApprovedAt,
    string Source,
    DateTimeOffset ReceivedAt,
    string Status,
    DateTimeOffset? DoneAt);

/// <summary>Limits shared by the ledger and the HTTP layer.</summary>
public static class AdviceLimits
{
    public const int MaxBodyBytes = 16 * 1024;
    public const int MaxTitle = 120;
    public const int MaxRecommendation = 2000;
    public const int MaxCommand = 4000;
    public const int MaxId = 200;
    public const int MaxField = 200;   // findingId, approvedBy
    public const int MaxIp = 64;
    public const int MaxSource = 64;
    public const int DefaultMaxItems = 500;
    public const string DefaultSource = "xrcopilotlab";
    public const string StatusReceived = "received";
    public const string StatusDone = "done";

    public static readonly IReadOnlyList<string> Severities = ["Low", "Medium", "High", "Critical"];
}

/// <summary>A body that does not meet the contract: the HTTP layer turns it into a 400.</summary>
public sealed class AdviceValidationException(string message) : Exception(message);
