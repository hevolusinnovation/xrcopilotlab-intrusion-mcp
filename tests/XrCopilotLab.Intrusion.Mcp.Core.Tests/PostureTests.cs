using XrCopilotLab.Intrusion.Mcp.Core.Analysis;
using XrCopilotLab.Intrusion.Mcp.Core.Geo;
using XrCopilotLab.Intrusion.Mcp.Core.Guard;
using XrCopilotLab.Intrusion.Mcp.Core.Models;
using XrCopilotLab.Intrusion.Mcp.Core.Queries;
using XrCopilotLab.Intrusion.Mcp.Core.Simulation;
using XrCopilotLab.Intrusion.Mcp.Core.Sources;
using Xunit;

namespace XrCopilotLab.Intrusion.Mcp.Core.Tests;

public class PostureTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 10, 14, 0, 0, TimeSpan.FromHours(1));

    private static GuardianFacts G(string name, bool installed = true, bool? running = true, string? mode = null, bool readable = true,
        DateTimeOffset? rules = null) =>
        new(name, installed, installed ? "1.0" : null, installed ? running : null, installed ? mode : null, false, $"/var/log/{name}.log", installed, readable,
            Now, rules);

    private static HostFacts Facts(IEnumerable<GuardianFacts> guardians, IEnumerable<ListeningPort>? listening = null, SshFacts? ssh = null) =>
        new(Now, guardians.ToList(), (listening ?? [new(22, "0.0.0.0", true)]).ToList(), ssh ?? new SshFacts(false, "prohibit-password", 22),
            Audit: AuditTests.Unchanged(Now));

    private static readonly GuardianFacts[] AllGood =
    [
        G("sshd"), G("nginx"), G("ufw", mode: "blocking"), G("fail2ban", mode: "blocking"), G("crowdsec", mode: "detection"),
        G("suricata", mode: "detection", rules: Now.AddHours(-8)), G("falco", mode: "detection"), G("modsecurity", mode: "detection"),
    ];

    private static SummaryResult Quiet() =>
        new IntrusionQueries(new EmptySource(), new NoGeoLocator(), new IntrusionPolicy()).Summary(Now, new Period(Now.AddDays(-7), Now), 100);

    [Fact]
    public void A_well_kept_quiet_host_has_nothing_to_fix()
    {
        Assert.Empty(PostureChecks.Evaluate(Facts(AllGood), Quiet()));
    }

    [Fact]
    public void Ssh_with_passwords_grows_from_medium_to_critical_with_the_evidence()
    {
        var facts = Facts(AllGood, ssh: new SshFacts(true, "prohibit-password", 22));
        Assert.Equal(nameof(Severity.Medium), Assert.Single(PostureChecks.Evaluate(facts, Quiet())).Severity);

        // The simulated night: brute force, then a login after the failures.
        var simulated = new IntrusionQueries(new SimulatedLogSource(new SimulationOptions()), new SyntheticGeo(), new IntrusionPolicy());
        var night = simulated.Summary(Now, simulated.Resolve(Now, 24, null, null), 100);
        var findings = PostureChecks.Evaluate(facts, night);
        Assert.Equal(nameof(Severity.Critical), findings.Single(f => f.Id == "ssh-password-auth").Severity);
        Assert.Contains(findings, f => f.Id == "incident-ssh-login" && f.Evidence.Contains(SyntheticHost.IncidentIp, StringComparison.Ordinal));
        Assert.Contains(findings, f => f.Id == "slow-brute-force-unbanned");
        // Incidents come first.
        Assert.Equal("incident", findings[0].Area);
    }

    [Fact]
    public void Modbus_open_to_the_network_is_critical_and_on_loopback_is_not()
    {
        var open = PostureChecks.Evaluate(Facts(AllGood, [new(22, "0.0.0.0", true), new(502, "0.0.0.0", true), new(6379, "127.0.0.1", false)]), Quiet());
        var modbus = Assert.Single(open);
        Assert.Equal(("exposed-industrial-502", nameof(Severity.Critical)), (modbus.Id, modbus.Severity));
    }

    [Fact]
    public void Missing_stopped_and_unreadable_guardians_each_say_what_to_do()
    {
        var facts = Facts(
        [
            G("sshd"), G("nginx"), G("ufw", installed: false), G("fail2ban", running: false, mode: "blocking"), G("crowdsec", installed: false),
            G("suricata", mode: "detection", rules: Now.AddDays(-9)), G("falco", installed: false), G("modsecurity", installed: false),
        ], ssh: new SshFacts(false, "yes", 22));
        var ids = PostureChecks.Evaluate(facts, Quiet()).Select(f => f.Id).ToList();
        Assert.Equivalent(new[] { "guardian-stopped-fail2ban", "fail2ban-missing", "ssh-root-login", "ids-rules-stale", "host-monitor-missing", "waf-missing", "firewall-off" }, ids);
        var fix = PostureChecks.Evaluate(facts, Quiet()).Single(f => f.Id == "waf-missing").Fix;
        Assert.Equal("sudo ./install.sh --with modsecurity", fix);
    }

    private sealed class EmptySource : ILogSource
    {
        public string Hostname => "web-01";
        public bool Simulated => false;
        public int MaxDays => 30;
        public IReadOnlyList<string> Describe() => [];
        public IReadOnlyList<LogEvent> Read(DateTimeOffset since, DateTimeOffset now) => [];
    }
}
