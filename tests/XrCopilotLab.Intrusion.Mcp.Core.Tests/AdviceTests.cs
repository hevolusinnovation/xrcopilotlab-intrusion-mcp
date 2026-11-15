using XrCopilotLab.Intrusion.Mcp.Core.Advice;
using XrCopilotLab.Intrusion.Mcp.Core.Guard;
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

    private static PostureFinding Finding(string id) => new(id, "High", "network", "t", $"evidence of {id}", "r", null);

    [Fact]
    public void Advice_is_read_against_the_findings_of_now()
    {
        var ledger = new AdviceLedger();
        ledger.Upsert(Valid(id: "still") with { FindingId = "exposed-service-3389" }, Now);
        ledger.Upsert(Valid(id: "gone") with { FindingId = "ssh-password-auth" }, Now);
        ledger.Upsert(Valid(id: "attack") with { FindingId = "incident-ssh-login" }, Now);   // fires on attacks, not on configuration
        ledger.Upsert(Valid(id: "free") with { FindingId = null }, Now);
        ledger.MarkDone("still", Now.AddMinutes(5));

        var views = AdviceVerifier.Verify(ledger.List(Now, null), [Finding("exposed-service-3389")]).ToDictionary(v => v.Id);

        // Marked done, and the port is still open: the page and the agent can say it did not take effect.
        Assert.Equal((AdviceLimits.StatusDone, AdviceVerifier.Open), (views["still"].Status, views["still"].Verification));
        Assert.Equal("evidence of exposed-service-3389", views["still"].Evidence);
        // Never marked, yet fixed on the host.
        Assert.Equal((AdviceLimits.StatusReceived, AdviceVerifier.Fixed), (views["gone"].Status, views["gone"].Verification));
        // A silent incident proves nothing; advice with no finding has nothing to be read against.
        Assert.Equal(AdviceVerifier.Unknown, views["attack"].Verification);
        Assert.Equal(AdviceVerifier.Unknown, views["free"].Verification);
    }

    [Theory]
    [InlineData("ssh-password-auth", true)]
    [InlineData("exposed-ai-11434", true)]
    [InlineData("guardian-stopped-falco", true)]
    [InlineData("incident-c2", false)]
    [InlineData("slow-brute-force-unbanned", false)]
    [InlineData("waf-detection-only", false)]
    [InlineData("made-up", false)]
    public void Only_configuration_findings_can_be_verified(string id, bool expected) =>
        Assert.Equal(expected, PostureChecks.ReadsConfiguration(id));
}
