using XrCopilotLab.Intrusion.Mcp.Core.Guard;

namespace XrCopilotLab.Intrusion.Mcp.Core.Advice;

/// <summary>
/// One piece of advice as the page and the agent see it: what was stored (<see cref="AdviceItem"/>) plus what the host
/// says now. <c>Verification</c>: <c>open</c> (the check the advice came from still fires: <c>Evidence</c> says why),
/// <c>fixed</c> (it no longer fires) or <c>unknown</c> (no <c>FindingId</c>, or a finding that depends on the attacks of
/// the period and not on the configuration, so its silence proves nothing). <c>Status</c> stays what a person said
/// (<c>received</c>, <c>done</c>): <c>done</c> with <c>open</c> is advice marked done that did not take effect.
/// </summary>
public sealed record AdviceView(
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
    DateTimeOffset? DoneAt,
    string Verification,
    string? Evidence);

/// <summary>Reads the stored advice against the posture findings of now. Pure: it changes neither.</summary>
public static class AdviceVerifier
{
    public const string Open = "open";
    public const string Fixed = "fixed";
    public const string Unknown = "unknown";

    public static IReadOnlyList<AdviceView> Verify(IReadOnlyList<AdviceItem> advice, IReadOnlyList<PostureFinding> findings)
    {
        var firing = findings.GroupBy(f => f.Id, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        return advice.Select(a =>
        {
            var (verification, evidence) = a.FindingId is not { } id || !PostureChecks.ReadsConfiguration(id) ? (Unknown, null)
                : firing.TryGetValue(id, out var f) ? (Open, f.Evidence)
                : (Fixed, (string?)null);
            return new AdviceView(a.Id, a.FindingId, a.Ip, a.Severity, a.Title, a.Recommendation, a.Command, a.ApprovedBy, a.ApprovedAt, a.Source,
                a.ReceivedAt, a.Status, a.DoneAt, verification, evidence);
        }).ToList();
    }
}
