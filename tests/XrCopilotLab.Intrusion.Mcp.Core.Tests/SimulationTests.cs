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

        var events = LogLines.Parse(day.Fail2banLines, day.AuthLines, rome, Now).ToList();

        Assert.Equal(day.Fail2banLines.Count, events.Count(e => e.Origin == LogOrigin.Fail2ban));
        Assert.NotEmpty(events);
        Assert.All(events, e => Assert.True(IpScope.IsDocumentation(e.SourceIp), $"{e.SourceIp} is not a documentation address"));
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
}
