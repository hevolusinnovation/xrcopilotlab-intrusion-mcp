using XrCopilotLab.Intrusion.Mcp.Core.Analysis;
using XrCopilotLab.Intrusion.Mcp.Core.Geo;
using XrCopilotLab.Intrusion.Mcp.Core.Models;
using XrCopilotLab.Intrusion.Mcp.Core.Queries;
using XrCopilotLab.Intrusion.Mcp.Core.Simulation;
using XrCopilotLab.Intrusion.Mcp.Core.Sources;
using Xunit;

namespace XrCopilotLab.Intrusion.Mcp.Core.Tests;

/// <summary>
/// The simulated host is what the demo shows: these tests say the story it tells is the one the README promises,
/// and that it goes through the same parsers and rules as a real host.
/// </summary>
public class SimulationTests
{
    private static readonly SimulationOptions Options = new();
    // 14:00 in Rome: the night's intrusion is in the last 24 hours.
    private static readonly DateTimeOffset Now = new(2026, 11, 10, 14, 0, 0, TimeSpan.FromHours(1));

    private static IntrusionQueries Queries() => new(new SimulatedLogSource(Options), new SyntheticGeo(), new IntrusionPolicy());

    [Fact]
    public void The_same_day_always_gives_the_same_lines()
    {
        var day = new DateOnly(2026, 11, 10);
        var a = new SyntheticHost(Options).Generate(day);
        var b = new SyntheticHost(Options).Generate(day);

        Assert.Equal(a.Fail2banLines, b.Fail2banLines);
        Assert.Equal(a.AuthLines, b.AuthLines);
        Assert.NotEqual(a.AuthLines, new SyntheticHost(Options).Generate(day.AddDays(1)).AuthLines);
    }

    [Fact]
    public void Every_simulated_line_parses_and_every_address_is_a_documentation_address()
    {
        var day = new SyntheticHost(Options).Generate(new DateOnly(2026, 11, 10));
        var rome = TimeZoneInfo.FindSystemTimeZoneById(Options.TimeZone);

        var events = LogLines.Parse(day.ToLogSet(), rome, Now).ToList();

        Assert.Equal(day.Fail2banLines.Count, events.Count(e => e.Origin == LogOrigin.Fail2ban));
        Assert.Equal(day.FirewallLines.Count, events.Count(e => e.Origin == LogOrigin.Firewall));
        Assert.Equal(day.CrowdsecLines.Count, events.Count(e => e.Origin == LogOrigin.Crowdsec));
        // Suricata's engine events (priority 3) are in eve.json but are not events.
        Assert.True(day.SuricataLines.Count > events.Count(e => e.Origin == LogOrigin.Suricata));
        Assert.Contains(events, e => e.Origin == LogOrigin.Suricata);
        // Ordinary web traffic is in the log but is not an event.
        Assert.True(day.WebAccessLines.Count > events.Count(e => e.Origin == LogOrigin.WebAccess));
        Assert.Contains(events, e => e.Origin == LogOrigin.WebAccess);
        // Falco's lines are all events; only those of an SSH session carry an address (SSH_CLIENT).
        Assert.Equal(day.FalcoLines.Count, events.Count(e => e.Origin == LogOrigin.Falco));
        Assert.All(events.Where(e => e.Origin == LogOrigin.Falco && e.HasAddress), e => Assert.Equal("ssh-session", e.LinkedBy));
        Assert.Contains(events, e => e.Origin == LogOrigin.Falco && !e.HasAddress);
        // Every audit entry is above the CRS blocking score: each one is an event.
        Assert.Equal(day.ModSecurityLines.Count, events.Count(e => e.Origin == LogOrigin.ModSecurity));
        Assert.Contains(events, e => e.Origin == LogOrigin.ModSecurity && e.Method == "POST");
        Assert.NotEmpty(events);
        Assert.All(events.Where(e => e.HasAddress), e => Assert.True(IpScope.IsDocumentation(e.SourceIp), $"{e.SourceIp} is not a documentation address"));
    }

    [Fact]
    public void The_night_intrusion_is_never_banned_and_is_critical()
    {
        var q = Queries();
        var period = q.Resolve(Now, 24, null, null);

        var login = Assert.Single(q.SuspiciousLogins(Now, period).Suspicious, s => s.Ip == SyntheticHost.IncidentIp);
        Assert.Equal((SyntheticHost.IncidentUser, "after-failures"), (login.User, login.Reason));
        Assert.True(login.FailuresBefore >= 30);

        var detail = q.IpDetail(Now, period, SyntheticHost.IncidentIp);
        Assert.Equal(nameof(Severity.Critical), detail.Report!.Severity);
        Assert.Equal(0, detail.Report.Bans);
        Assert.Equal("MD", detail.Report.Location.CountryCode);
    }

    [Fact]
    public void Legitimate_logins_are_not_reported()
    {
        var q = Queries();
        var period = q.Resolve(Now, 24, null, null);

        var suspicious = q.SuspiciousLogins(Now, period);
        Assert.True(suspicious.SuccessfulLogins > suspicious.Suspicious.Count);
        Assert.DoesNotContain(suspicious.Suspicious, s => s.Ip is SyntheticHost.OfficeIp or SyntheticHost.AdminIp or SyntheticHost.BackupIp);
        Assert.Null(q.IpDetail(Now, period, SyntheticHost.AdminIp).Report);
    }

    [Fact]
    public void The_summary_tells_the_whole_story()
    {
        var q = Queries();
        var summary = q.Summary(Now, q.Resolve(Now, 24, null, null), 10);

        Assert.True(summary.Simulated);
        Assert.True(summary.Totals.Bans > 10);
        Assert.True(summary.Totals.CurrentlyBanned > 0);
        Assert.NotEmpty(summary.Campaigns);
        Assert.Contains(summary.ByAttackType, t => t.Type == nameof(AttackType.SshBruteForce));
        Assert.Contains(summary.ByAttackType, t => t.Type == nameof(AttackType.WebVulnerabilityScan));
        Assert.Contains(summary.ByAttackType, t => t.Type == nameof(AttackType.RepeatOffender));
        Assert.Equal(SyntheticHost.IncidentIp, summary.TopAttackers[0].Ip);
        Assert.NotEmpty(summary.MapPoints);
        Assert.Equal(SyntheticGeo.SimulatedAttribution, summary.GeoAttribution);
    }

    [Fact]
    public void A_repeat_offender_stays_banned_by_recidive()
    {
        var q = Queries();
        var banned = q.Banned(Now, "recidive");

        Assert.NotEmpty(banned.Banned);
        Assert.All(banned.Banned, b => Assert.Equal(nameof(AttackType.RepeatOffender), b.AttackType));
    }

    [Fact]
    public void Today_is_cut_at_now()
    {
        var source = new SimulatedLogSource(Options);
        var early = new DateTimeOffset(2026, 11, 10, 1, 0, 0, TimeSpan.FromHours(1));

        Assert.All(source.Read(early.AddHours(-2), early), e => Assert.True(e.Time <= early));
        Assert.DoesNotContain(source.Read(early.AddHours(-2), early), e => e.Kind == LogEventKind.AcceptedLogin && e.SourceIp == SyntheticHost.IncidentIp);
    }

    [Fact]
    public void After_the_login_the_host_calls_a_malware_controller_and_suricata_sees_it()
    {
        var q = Queries();
        var period = q.Resolve(Now, 24, null, null);
        var controller = q.IpDetail(Now, period, SyntheticHost.ControllerIp);
        var report = controller.Report!;

        Assert.Equal(nameof(Severity.Critical), report.Severity);
        Assert.Contains(nameof(AttackType.CommandAndControl), report.AttackTypes);
        var signature = Assert.Single(report.IdsSignatures);
        Assert.True(signature.Outbound);

        var login = q.IpDetail(Now, period, SyntheticHost.IncidentIp).Timeline.Single(t => t.Kind == nameof(LogEventKind.AcceptedLogin)).Time;
        Assert.All(controller.Timeline, t => Assert.True(t.Time > login && t.Outbound));
        Assert.Contains(q.Summary(Now, period, 10).ByAttackType, t => t.Type == nameof(AttackType.CommandAndControl));
    }

    [Fact]
    public void What_the_intruder_did_once_in_is_tied_to_the_address_that_got_in()
    {
        var q = Queries();
        var period = q.Resolve(Now, 24, null, null);
        var intruder = q.IpDetail(Now, period, SyntheticHost.IncidentIp);

        var activity = intruder.Report!.HostActivity;
        Assert.Equal(["Clear Log Activities", "Execution from /dev/shm", "Read sensitive file untrusted", "Search Private Keys or Passwords",
            "XRC Crypto miner started", "XRC SSH authorized keys changed"], activity.Select(a => a.Rule).Order(StringComparer.Ordinal));
        Assert.All(activity, a => Assert.Equal("ssh-session", a.LinkedBy));
        foreach (var type in new[] { AttackType.SensitiveFileAccess, AttackType.Persistence, AttackType.SuspiciousExecution, AttackType.CryptoMining, AttackType.LogTampering })
            Assert.Contains(type.ToString(), intruder.Report.AttackTypes);

        var login = intruder.Timeline.Single(t => t.Kind == nameof(LogEventKind.AcceptedLogin)).Time;
        Assert.All(intruder.Timeline.Where(t => t.Kind == nameof(LogEventKind.HostAlert)), t => Assert.True(t.Time > login && t.LinkedBy == "ssh-session"));
    }

    [Fact]
    public void The_inventory_agent_stays_the_hosts_and_is_not_an_attacker()
    {
        var q = Queries();
        var host = q.HostActivity(Now, q.Resolve(Now, 24, null, null), null, unlinkedOnly: true);

        var agent = Assert.Single(host.Timeline, a => a.Command!.Contains("/opt/inventory/agent.py", StringComparison.Ordinal));
        Assert.Null(agent.Ip);
        Assert.Equal(nameof(Severity.High), agent.Severity);
        Assert.True(host.Unlinked >= 1);
        Assert.True(q.Summary(Now, q.Resolve(Now, 24, null, null), 10).Totals.HostAlerts >= 7);
    }

    [Fact]
    public void Suricata_flags_reputation_and_exploits_and_drops_engine_noise()
    {
        var q = Queries();
        var summary = q.Summary(Now, q.Resolve(Now, 24, null, null), 50);

        Assert.True(summary.Totals.IdsAlerts > 0);
        Assert.Contains(summary.ByAttackType, t => t.Type == nameof(AttackType.KnownMaliciousSource));
        Assert.Contains(summary.ByAttackType, t => t.Type == nameof(AttackType.NetworkExploitAttempt));
        Assert.DoesNotContain(summary.TopAttackers.SelectMany(r => r.IdsSignatures), s => s.Signature.StartsWith("SURICATA STREAM", StringComparison.Ordinal));
    }

    [Fact]
    public void The_intruder_scanned_the_ports_and_crowdsec_saw_it_before_the_login()
    {
        var q = Queries();
        var detail = q.IpDetail(Now, q.Resolve(Now, 24, null, null), SyntheticHost.IncidentIp);
        var report = detail.Report!;

        Assert.Contains(nameof(AttackType.PortScan), report.AttackTypes);
        Assert.Contains("crowdsecurity/ssh-slow-bf", report.CrowdsecScenarios);
        Assert.Contains("crowdsecurity/iptables-scan-multi_ports", report.CrowdsecScenarios);

        var login = detail.Timeline.Single(t => t.Kind == nameof(LogEventKind.AcceptedLogin)).Time;
        var firstBlock = detail.Timeline.Where(t => t.Kind == nameof(LogEventKind.FirewallBlock)).Min(t => t.Time);
        var slowBf = detail.Timeline.Single(t => t.Kind == nameof(LogEventKind.CrowdsecAlert) && t.Rule == "crowdsecurity/ssh-slow-bf").Time;
        Assert.True(firstBlock < slowBf && slowBf < login);
    }

    [Fact]
    public void An_industrial_probe_and_web_exploits_are_high()
    {
        var q = Queries();
        var attempts = q.Attempts(Now, q.Resolve(Now, 24, null, null), null, null, null, 100).Top;

        // One probe a day: a 24-hour window can hold two.
        var ics = attempts.Where(r => r.AttackTypes.Contains(nameof(AttackType.IndustrialProtocolProbe)) && r.Ip.StartsWith("203.", StringComparison.Ordinal)).ToList();
        Assert.NotEmpty(ics);
        Assert.All(ics, r => Assert.Equal(nameof(Severity.High), r.Severity));
        Assert.Contains(ics[0].PortsProbed, p => p.Port == 502 && p.Service == "Modbus/TCP");

        var exploits = attempts.Where(r => r.AttackTypes.Contains(nameof(AttackType.WebExploitAttempt))).ToList();
        Assert.NotEmpty(exploits);
        Assert.All(exploits, r => Assert.True(r.WebProbes.Count + r.WafFindings.Count > 0));
        // Injections hidden in a POST body: the access log shows nothing, only the WAF has them.
        Assert.Contains(exploits, r => r.WebProbes.Count == 0 && r.WafFindings.Any(f => f.Example == "POST /contact.php"));
    }

    [Fact]
    public void Ordinary_visitors_and_firewall_noise_are_not_reported()
    {
        var q = Queries();
        var attempts = q.Attempts(Now, q.Resolve(Now, 24, null, null), null, null, null, 100);

        Assert.DoesNotContain(attempts.Top, r => r.Location.CountryCode == "IT");
        Assert.All(attempts.Top, r => Assert.NotEmpty(r.AttackTypes));
    }

    [Fact]
    public void Consecutive_slots_touch_without_overlapping()
    {
        var q = Queries();
        var at1047 = new DateTimeOffset(2026, 11, 10, 10, 47, 12, TimeSpan.FromHours(1));

        var slot = q.Resolve(at1047, null, null, null, 30);
        var next = q.Resolve(at1047.AddMinutes(30), null, null, null, 30);

        Assert.Equal(new DateTimeOffset(2026, 11, 10, 9, 0, 0, TimeSpan.Zero), slot.From);
        Assert.Equal(new DateTimeOffset(2026, 11, 10, 9, 30, 0, TimeSpan.Zero), slot.To);
        Assert.Equal(slot.To, next.From);
    }
}
