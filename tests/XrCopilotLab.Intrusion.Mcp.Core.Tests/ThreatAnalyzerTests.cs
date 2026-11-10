using XrCopilotLab.Intrusion.Mcp.Core.Analysis;
using XrCopilotLab.Intrusion.Mcp.Core.Geo;
using XrCopilotLab.Intrusion.Mcp.Core.Models;
using Xunit;

namespace XrCopilotLab.Intrusion.Mcp.Core.Tests;

public class ThreatAnalyzerTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 10, 1, 0, 0, TimeSpan.FromHours(1));
    private readonly ThreatAnalyzer _analyzer = new(new IntrusionPolicy(), new NoGeoLocator());

    private static LogEvent Fail(int minute, string ip, string user = "root") =>
        new(T0.AddMinutes(minute), LogEventKind.FailedLogin, LogOrigin.Auth, ip, User: user, Port: 40000, Method: "password");

    private static LogEvent Login(int minute, string ip, string user) =>
        new(T0.AddMinutes(minute), LogEventKind.AcceptedLogin, LogOrigin.Auth, ip, User: user, Port: 40000, Method: "password");

    private static LogEvent F2b(int minute, LogEventKind kind, string ip, string jail = "sshd") =>
        new(T0.AddMinutes(minute), kind, LogOrigin.Fail2ban, ip, Jail: jail);

    [Fact]
    public void A_login_after_repeated_failures_is_critical()
    {
        var events = new List<LogEvent>();
        for (var i = 0; i < 6; i++) events.Add(Fail(i * 3, "203.0.113.9", "operatore"));
        events.Add(Login(20, "203.0.113.9", "operatore"));

        var report = Assert.Single(_analyzer.Reports(events, []));
        Assert.Equal(nameof(Severity.Critical), report.Severity);
        Assert.Contains(nameof(AttackType.LoginAfterFailures), report.AttackTypes);
        var login = Assert.Single(_analyzer.SuspiciousLogins(events));
        Assert.Equal(("after-failures", 6), (login.Reason, login.FailuresBefore));
    }

    [Fact]
    public void A_user_who_mistypes_once_is_not_an_attacker()
    {
        var events = new List<LogEvent> { Fail(0, "198.51.100.10", "m.ferri"), Login(1, "198.51.100.10", "m.ferri") };

        Assert.Empty(_analyzer.Reports(events, []));
        Assert.Empty(_analyzer.SuspiciousLogins(events));
    }

    [Fact]
    public void An_address_is_banned_until_its_unban()
    {
        var events = new[]
        {
            F2b(0, LogEventKind.Ban, "203.0.113.1"),
            F2b(60, LogEventKind.Unban, "203.0.113.1"),
            F2b(10, LogEventKind.Ban, "203.0.113.2"),
            F2b(10, LogEventKind.Ban, "203.0.113.2", "recidive"),
            F2b(70, LogEventKind.Unban, "203.0.113.2"),
        };

        var banned = Assert.Single(ThreatAnalyzer.CurrentBans(events));
        Assert.Equal(("203.0.113.2", "recidive"), (banned.Ip, banned.Jail));
    }

    [Fact]
    public void Sshd_attempts_are_counted_once_when_auth_log_is_there()
    {
        var events = new List<LogEvent>();
        for (var i = 0; i < 5; i++) { events.Add(Fail(i, "203.0.113.3")); events.Add(F2b(i, LogEventKind.Found, "203.0.113.3")); }
        events.Add(F2b(5, LogEventKind.Ban, "203.0.113.3"));

        var report = Assert.Single(_analyzer.Reports(events, []));
        Assert.Equal((5, 1), (report.Attempts, report.Bans));
        Assert.Equal(nameof(Severity.Medium), report.Severity);
        Assert.Equal([nameof(AttackType.SshBruteForce)], report.AttackTypes);
    }

    [Fact]
    public void Many_addresses_on_one_account_under_the_threshold_are_a_campaign()
    {
        var events = Enumerable.Range(1, 10).SelectMany(i => new[] { Fail(i * 30, $"192.0.2.{i}", "scada"), Fail(i * 30 + 20, $"192.0.2.{i}", "scada") }).ToList();

        var campaign = Assert.Single(_analyzer.Campaigns(events, new HashSet<string>()));
        Assert.Equal(("scada", 10, 20, 0), (campaign.User, campaign.Addresses, campaign.Attempts, campaign.BannedAddresses));
        Assert.All(_analyzer.Reports(events, []), r => Assert.Equal([nameof(AttackType.DistributedSshBruteForce)], r.AttackTypes));
    }

    [Fact]
    public void A_single_ban_seen_by_recidive_is_not_a_repeat_offender()
    {
        var events = new List<LogEvent>();
        for (var i = 0; i < 5; i++) events.Add(Fail(i, "203.0.113.4"));
        events.Add(F2b(5, LogEventKind.Ban, "203.0.113.4"));
        events.Add(F2b(5, LogEventKind.Found, "203.0.113.4", "recidive"));

        Assert.DoesNotContain(nameof(AttackType.RepeatOffender), Assert.Single(_analyzer.Reports(events, [])).AttackTypes);

        events.Add(F2b(6, LogEventKind.Ban, "203.0.113.4", "recidive"));
        var report = Assert.Single(_analyzer.Reports(events, []));
        Assert.Contains(nameof(AttackType.RepeatOffender), report.AttackTypes);
        Assert.Equal(nameof(Severity.High), report.Severity);
    }

    [Fact]
    public void Web_scans_are_classified_from_the_jail()
    {
        var events = Enumerable.Range(0, 4).Select(i => F2b(i, LogEventKind.Found, "198.51.100.150", "nginx-botsearch")).ToList();

        var report = Assert.Single(_analyzer.Reports(events, []));
        Assert.Equal([nameof(AttackType.WebVulnerabilityScan)], report.AttackTypes);
        Assert.Equal(4, report.Attempts);
    }
}
