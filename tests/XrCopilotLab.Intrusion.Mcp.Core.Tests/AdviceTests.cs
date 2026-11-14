using XrCopilotLab.Intrusion.Mcp.Core.Advice;
using Xunit;

namespace XrCopilotLab.Intrusion.Mcp.Core.Tests;

public class AdviceTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 14, 10, 0, 0, TimeSpan.Zero);

    private static AdviceRequest Valid(string id = "inst-1", string? severity = "high", string? title = "Chiudi 3389 a internet") =>
        new(id, "exposed-service-3389", "198.51.100.7", severity, title,
            "Consenti RDP solo dalla VPN e chiudi la porta al mondo.", "sudo ufw deny 3389",
            "Giulia (responsabile SOC)", Now, null);

    [Fact]
    public void A_valid_request_is_received_and_normalized()
    {
        var ledger = new AdviceLedger();
        var (item, created) = ledger.Upsert(Valid(), Now);

        Assert.True(created);
        Assert.Equal("inst-1", item.Id);
        Assert.Equal("High", item.Severity);               // canonical case
        Assert.Equal("xrcopilotlab", item.Source);         // defaulted
        Assert.Equal(AdviceLimits.StatusReceived, item.Status);
        Assert.Equal(Now, item.ReceivedAt);
        Assert.Null(item.DoneAt);
    }

    [Fact]
    public void The_same_id_updates_and_never_duplicates()
    {
        var ledger = new AdviceLedger();
        ledger.Upsert(Valid(title: "Prima"), Now);
        var (item, created) = ledger.Upsert(Valid(title: "Seconda") with { Severity = "critical" }, Now.AddMinutes(5));

        Assert.False(created);
        Assert.Equal("Seconda", item.Title);
        Assert.Equal("Critical", item.Severity);
        Assert.Equal(Now, item.ReceivedAt);                // kept from the first time
        Assert.Single(ledger.Snapshot());
    }

    [Fact]
    public void A_bad_body_is_rejected_with_every_problem()
    {
        var ledger = new AdviceLedger();
        var bad = new AdviceRequest(Id: "  ", FindingId: null, Ip: null, Severity: "urgente",
            Title: null, Recommendation: "ok", Command: null, ApprovedBy: null, ApprovedAt: null, Source: null);

        var ex = Assert.Throws<AdviceValidationException>(() => ledger.Upsert(bad, Now));
        Assert.Contains("id is required", ex.Message);
        Assert.Contains("title is required", ex.Message);
        Assert.Contains("severity must be one of", ex.Message);
        Assert.Contains("approvedBy is required", ex.Message);
        Assert.Contains("approvedAt is required", ex.Message);
    }

    [Fact]
    public void Over_length_title_is_rejected()
    {
        var ledger = new AdviceLedger();
        var ex = Assert.Throws<AdviceValidationException>(
            () => ledger.Upsert(Valid(title: new string('x', AdviceLimits.MaxTitle + 1)), Now));
        Assert.Contains($"title is longer than {AdviceLimits.MaxTitle}", ex.Message);
    }

    [Fact]
    public void Listing_is_newest_first_and_can_filter_by_hours()
    {
        var ledger = new AdviceLedger();
        ledger.Upsert(Valid(id: "old"), Now.AddHours(-48));
        ledger.Upsert(Valid(id: "new"), Now.AddHours(-1));

        var all = ledger.List(Now, null);
        Assert.Equal(["new", "old"], all.Select(a => a.Id));

        var recent = ledger.List(Now, hours: 24);
        Assert.Equal(["new"], recent.Select(a => a.Id));
    }

    [Fact]
    public void Mark_done_is_idempotent_and_false_for_an_unknown_id()
    {
        var ledger = new AdviceLedger();
        ledger.Upsert(Valid(id: "inst-1"), Now);

        Assert.True(ledger.MarkDone("inst-1", Now.AddMinutes(10)));
        Assert.True(ledger.MarkDone("inst-1", Now.AddMinutes(20)));   // idempotent
        Assert.False(ledger.MarkDone("nope", Now));

        var item = ledger.List(Now, null).Single();
        Assert.Equal(AdviceLimits.StatusDone, item.Status);
        Assert.Equal(Now.AddMinutes(10), item.DoneAt);               // first done time kept
    }

    [Fact]
    public void The_cap_keeps_only_the_newest()
    {
        var ledger = new AdviceLedger(maxItems: 3);
        for (var i = 0; i < 5; i++) ledger.Upsert(Valid(id: $"inst-{i}"), Now.AddMinutes(i));

        var ids = ledger.List(Now.AddHours(1), null).Select(a => a.Id).ToArray();
        Assert.Equal(["inst-4", "inst-3", "inst-2"], ids);
    }
}
