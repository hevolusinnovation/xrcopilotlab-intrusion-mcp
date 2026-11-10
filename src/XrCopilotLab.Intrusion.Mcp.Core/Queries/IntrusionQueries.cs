using XrCopilotLab.Intrusion.Mcp.Core.Analysis;
using XrCopilotLab.Intrusion.Mcp.Core.Geo;
using XrCopilotLab.Intrusion.Mcp.Core.Models;
using XrCopilotLab.Intrusion.Mcp.Core.Sources;

namespace XrCopilotLab.Intrusion.Mcp.Core.Queries;

/// <summary>The answers behind the MCP tools. Read-only: nothing here bans, unbans or writes.</summary>
public sealed class IntrusionQueries(ILogSource source, IGeoLocator geo, IntrusionPolicy policy)
{
    public const int DefaultHours = 24;
    public const int MaxTop = 100;
    public const int MaxTimeline = 200;
    public const int MaxMapPoints = 150;

    private readonly ThreatAnalyzer _analyzer = new(policy, geo);

    /// <summary>The period of a call: explicit bounds win, otherwise the last <paramref name="hours"/> hours.</summary>
    public Period Resolve(DateTimeOffset now, int? hours, DateTimeOffset? since, DateTimeOffset? until)
    {
        var to = until is { } u && u < now ? u : now;
        var maxHours = source.MaxDays * 24;
        var from = since ?? to.AddHours(-Math.Clamp(hours ?? DefaultHours, 1, maxHours));
        if (from < now.AddDays(-source.MaxDays)) from = now.AddDays(-source.MaxDays);
        if (from > to) from = to;
        return new Period(from, to);
    }

    public StatusResult Status(DateTimeOffset now)
    {
        var history = source.Read(now.AddDays(-source.MaxDays), now);
        var bans = ThreatAnalyzer.CurrentBans(history);
        var day = history.Where(e => e.Time >= now.AddHours(-24)).ToList();
        var authAvailable = day.Any(e => e.Origin == LogOrigin.Auth);

        var jails = history.Where(e => e.Jail is not null).Select(e => e.Jail!).Distinct().Order()
            .Select(j => new JailStatus(
                j,
                AttackCatalog.FromJail(j).ToString(),
                bans.Count(b => b.Jail == j),
                day.Count(e => e.Jail == j && e.Kind == LogEventKind.Ban),
                string.Equals(j, AttackCatalog.SshJail, StringComparison.OrdinalIgnoreCase) && authAvailable
                    ? day.Count(e => e.Kind == LogEventKind.FailedLogin)
                    : AttackCatalog.CountsAttempts(j) ? day.Count(e => e.Jail == j && e.Kind == LogEventKind.Found) : 0))
            .ToList();

        var detectors = history.GroupBy(e => e.Origin)
            .Select(g => new DetectorStatus(DetectorName(g.Key), g.Count(e => e.Time >= now.AddHours(-24)), g.Max(e => e.Time)))
            .OrderBy(d => d.Detector, StringComparer.Ordinal)
            .ToList();

        return new StatusResult(source.Hostname, source.Simulated, source.Describe(), now,
            history.Count > 0 ? history[0].Time : null,
            history.Count > 0 ? history[^1].Time : null,
            day.Count,
            bans.Select(b => b.Ip).Distinct().Count(),
            detectors,
            jails,
            geo.Attribution);
    }

    public BannedResult Banned(DateTimeOffset now, string? jail)
    {
        var bans = ThreatAnalyzer.CurrentBans(source.Read(now.AddDays(-source.MaxDays), now))
            .Where(b => jail is null || string.Equals(b.Jail, jail, StringComparison.OrdinalIgnoreCase))
            .Select(b => new BannedIp(b.Ip, b.Jail, AttackCatalog.FromJail(b.Jail).ToString(), b.Since, geo.Locate(b.Ip)))
            .ToList();
        return new BannedResult(source.Hostname, source.Simulated, now, bans.Count, bans, geo.Attribution);
    }

    public AttemptsResult Attempts(DateTimeOffset now, Period period, string? jail, string? attackType, string? country, int top)
    {
        var reports = Reports(now, period)
            .Where(r => jail is null || r.Jails.Contains(jail, StringComparer.OrdinalIgnoreCase))
            .Where(r => attackType is null || r.AttackTypes.Contains(attackType, StringComparer.OrdinalIgnoreCase))
            .Where(r => country is null || string.Equals(r.Location.CountryCode, country, StringComparison.OrdinalIgnoreCase))
            .ToList();
        return new AttemptsResult(source.Hostname, source.Simulated, period, reports.Count, reports.Take(Math.Clamp(top, 1, MaxTop)).ToList(), geo.Attribution);
    }

    public IpDetailResult IpDetail(DateTimeOffset now, Period period, string ip)
    {
        var events = Window(now, period);
        // The 24 hours before the period only serve to judge its logins: the timeline is the period.
        var own = events.Where(e => e.SourceIp == ip && e.Time >= period.From).ToList();
        var report = Reports(now, period).FirstOrDefault(r => r.Ip == ip);
        var timeline = own
            .Where(e => e.Kind != LogEventKind.InvalidUser)
            .OrderByDescending(e => e.Time)
            .Take(MaxTimeline)
            .Select(e => new TimelineEntry(e.Time, e.Kind.ToString(), DetectorName(e.Origin), e.Jail, e.User, e.Port, e.Method,
                e.TargetPort, e.Path, e.Status, e.Rule, e.Detail))
            .ToList();
        return new IpDetailResult(source.Hostname, source.Simulated, period, report,
            _analyzer.SuspiciousLogins(events).Where(s => s.Ip == ip && s.Time >= period.From).ToList(),
            own.Count(e => e.Kind != LogEventKind.InvalidUser), timeline, geo.Attribution);
    }

    public SuspiciousLoginsResult SuspiciousLogins(DateTimeOffset now, Period period)
    {
        var events = Window(now, period);
        return new SuspiciousLoginsResult(source.Hostname, source.Simulated, period,
            events.Count(e => e.Kind == LogEventKind.AcceptedLogin && e.Time >= period.From),
            _analyzer.SuspiciousLogins(events).Where(s => s.Time >= period.From).ToList(), geo.Attribution);
    }

    public SummaryResult Summary(DateTimeOffset now, Period period, int top)
    {
        var events = Window(now, period);
        var inPeriod = events.Where(e => e.Time >= period.From).ToList();
        var bans = ThreatAnalyzer.CurrentBans(source.Read(now.AddDays(-source.MaxDays), now));
        var reports = _analyzer.Reports(inPeriod, bans);
        var suspicious = _analyzer.SuspiciousLogins(events).Where(s => s.Time >= period.From).ToList();
        var campaigns = _analyzer.Campaigns(inPeriod, inPeriod.Where(e => e.Kind == LogEventKind.Ban).Select(e => e.SourceIp).ToHashSet());

        var byType = reports
            .SelectMany(r => r.AttackTypes.Select(t => (Type: t, r.Attempts)))
            .GroupBy(x => x.Type)
            .Select(g => new AttackTypeCount(g.Key, AttackCatalog.Describe(Enum.Parse<AttackType>(g.Key)), g.Count(), g.Sum(x => x.Attempts)))
            .OrderByDescending(x => x.Attempts)
            .ToList();
        var byCountry = reports
            .GroupBy(r => r.Location.CountryCode)
            .Select(g => new CountryCount(g.Key, g.First().Location.Country, g.Count(), g.Sum(r => r.Attempts)))
            .OrderByDescending(c => c.Attempts)
            .Take(20)
            .ToList();
        var points = reports
            .Where(r => r.Location.Latitude is not null && r.Location.Longitude is not null)
            .Take(MaxMapPoints)
            .Select(r => new MapPoint(r.Ip, r.Location.Latitude!.Value, r.Location.Longitude!.Value, r.Location.Country, r.Location.City, r.Severity, r.Attempts, r.AttackTypes))
            .ToList();

        var totals = new SummaryTotals(
            reports.Sum(r => r.Attempts),
            reports.Count,
            inPeriod.Count(e => e.Kind == LogEventKind.Ban),
            bans.Select(b => b.Ip).Distinct().Count(),
            inPeriod.Count(e => e.Kind == LogEventKind.AcceptedLogin),
            suspicious.Count,
            inPeriod.Count(e => e.Kind == LogEventKind.FirewallBlock),
            inPeriod.Count(e => e.Kind == LogEventKind.WebRequest),
            inPeriod.Count(e => e.Kind == LogEventKind.CrowdsecAlert));

        return new SummaryResult(source.Hostname, source.Simulated, period, totals, byType, byCountry, ThreatAnalyzer.TargetedPorts(inPeriod, 15),
            reports.Take(Math.Clamp(top, 1, MaxTop)).ToList(), campaigns, suspicious, points, geo.Attribution);
    }

    public static string DetectorName(LogOrigin origin) => origin switch
    {
        LogOrigin.Fail2ban => "fail2ban",
        LogOrigin.Auth => "sshd",
        LogOrigin.Firewall => "ufw",
        LogOrigin.WebAccess => "nginx",
        _ => "crowdsec",
    };

    private List<IpReport> Reports(DateTimeOffset now, Period period)
    {
        var inPeriod = Window(now, period).Where(e => e.Time >= period.From).ToList();
        var bans = ThreatAnalyzer.CurrentBans(source.Read(now.AddDays(-source.MaxDays), now));
        return _analyzer.Reports(inPeriod, bans).ToList();
    }

    /// <summary>The period plus the 24 hours before it: a login at the start of the period is judged on the failures that preceded it.</summary>
    private List<LogEvent> Window(DateTimeOffset now, Period period) =>
        source.Read(period.From.AddHours(-24), period.To).ToList();
}
