using XrCopilotLab.Intrusion.Mcp.Core.Geo;
using XrCopilotLab.Intrusion.Mcp.Core.Models;
using XrCopilotLab.Intrusion.Mcp.Core.Queries;

namespace XrCopilotLab.Intrusion.Mcp.Core.Analysis;

/// <summary>
/// Reads a period of events and says, per source address, what it did and how serious it is. Pure: the events, the
/// ban state and the geolocation come in as data.
/// </summary>
public sealed class ThreatAnalyzer(IntrusionPolicy policy, IGeoLocator geo)
{
    /// <summary>
    /// Which (address, jail) pairs are banned at the end of <paramref name="history"/>: the last ban start not followed by an unban.
    /// Read over the whole history, not the period, since a recidive ban lasts a week.
    /// </summary>
    public static IReadOnlyList<(string Ip, string Jail, DateTimeOffset Since)> CurrentBans(IEnumerable<LogEvent> history)
    {
        var state = new Dictionary<(string, string), DateTimeOffset?>();
        foreach (var e in history.Where(e => e.Origin == LogOrigin.Fail2ban && e.Jail is not null).OrderBy(e => e.Time))
        {
            if (e.IsBanStart) state[(e.SourceIp, e.Jail!)] = state.TryGetValue((e.SourceIp, e.Jail!), out var since) && since is not null ? since : e.Time;
            else if (e.Kind == LogEventKind.Unban) state[(e.SourceIp, e.Jail!)] = null;
        }
        return state.Where(kv => kv.Value is not null).Select(kv => (kv.Key.Item1, kv.Key.Item2, kv.Value!.Value)).OrderByDescending(b => b.Item3).ToList();
    }

    /// <summary>Successful logins that a person should look at: after repeated failures, or from an unexpected country.</summary>
    public IReadOnlyList<SuspiciousLogin> SuspiciousLogins(IReadOnlyList<LogEvent> period)
    {
        var failures = period.Where(e => e.Kind == LogEventKind.FailedLogin).GroupBy(e => e.SourceIp).ToDictionary(g => g.Key, g => g.Select(e => e.Time).ToList());
        var result = new List<SuspiciousLogin>();
        foreach (var login in period.Where(e => e.Kind == LogEventKind.AcceptedLogin))
        {
            var before = failures.TryGetValue(login.SourceIp, out var times)
                ? times.Count(t => t <= login.Time && login.Time - t <= TimeSpan.FromHours(24))
                : 0;
            var location = geo.Locate(login.SourceIp);
            if (before >= policy.FailuresBeforeLogin)
                result.Add(new SuspiciousLogin(login.Time, login.SourceIp, login.User ?? "", login.Method, location, before, "after-failures", nameof(Severity.Critical)));
            else if (location.Scope == GeoLocation.Public && !policy.IsAllowedCountry(location.CountryCode))
                result.Add(new SuspiciousLogin(login.Time, login.SourceIp, login.User ?? "", login.Method, location, before, "unexpected-country", nameof(Severity.High)));
        }
        return result.OrderByDescending(s => s.Time).ToList();
    }

    /// <summary>Accounts tried from many addresses, each staying under the ban threshold: the attack fail2ban alone does not stop.</summary>
    public IReadOnlyList<Campaign> Campaigns(IReadOnlyList<LogEvent> period, IReadOnlySet<string> bannedInPeriod)
    {
        var failures = period.Where(e => e.Kind == LogEventKind.FailedLogin && e.User is not null).ToList();
        var usersByIp = failures.GroupBy(e => e.SourceIp).ToDictionary(g => g.Key, g => g.Select(e => e.User!).Distinct().Count());

        var result = new List<Campaign>();
        foreach (var byUser in failures.GroupBy(e => e.User!))
        {
            // An address belongs to the campaign if it tried only this account, a few times.
            var members = byUser.GroupBy(e => e.SourceIp)
                .Where(g => usersByIp[g.Key] == 1 && g.Count() <= policy.CampaignMaxPerIp)
                .ToList();
            if (members.Count < policy.CampaignMinIps) continue;

            var events = members.SelectMany(g => g).ToList();
            result.Add(new Campaign(
                byUser.Key,
                members.Count,
                events.Count,
                members.Count(g => bannedInPeriod.Contains(g.Key)),
                members.Select(g => geo.Locate(g.Key).CountryCode).OfType<string>().Distinct().Order().ToList(),
                events.Min(e => e.Time),
                events.Max(e => e.Time)));
        }
        return result.OrderByDescending(c => c.Addresses).ToList();
    }

    public IReadOnlyList<IpReport> Reports(IReadOnlyList<LogEvent> period, IReadOnlyList<(string Ip, string Jail, DateTimeOffset Since)> currentBans)
    {
        var banned = currentBans.Select(b => b.Ip).ToHashSet();
        var bannedInPeriod = period.Where(e => e.Kind == LogEventKind.Ban).Select(e => e.SourceIp).ToHashSet();
        var campaignMembers = CampaignMembers(period, bannedInPeriod);
        var suspicious = SuspiciousLogins(period).ToLookup(s => s.Ip);
        // With auth.log available, sshd attempts are counted there (one per failed password), not twice through fail2ban.
        var authAvailable = period.Any(e => e.Origin == LogOrigin.Auth);

        var reports = new List<IpReport>();
        foreach (var byIp in period.GroupBy(e => e.SourceIp))
        {
            var events = byIp.ToList();
            var failures = events.Where(e => e.Kind == LogEventKind.FailedLogin).ToList();
            var found = events.Where(e => e.Kind == LogEventKind.Found && AttackCatalog.CountsAttempts(e.Jail!)
                                          && !(authAvailable && string.Equals(e.Jail, AttackCatalog.SshJail, StringComparison.OrdinalIgnoreCase))).ToList();
            var jails = events.Where(e => e.Jail is not null).Select(e => e.Jail!).Distinct().Order().ToList();

            // With auth.log, one sshd match is a mistyped password: brute force takes repeated failures or a ban.
            var sshBanned = events.Any(e => e.IsBanStart && string.Equals(e.Jail, AttackCatalog.SshJail, StringComparison.OrdinalIgnoreCase));
            // recidive writes a Found for every ban of every jail: an address is a repeat offender only once recidive bans it.
            var recidiveBanned = events.Any(e => e.IsBanStart && string.Equals(e.Jail, AttackCatalog.RecidiveJail, StringComparison.OrdinalIgnoreCase))
                                 || currentBans.Any(b => b.Ip == byIp.Key && string.Equals(b.Jail, AttackCatalog.RecidiveJail, StringComparison.OrdinalIgnoreCase));
            var types = new HashSet<AttackType>(jails
                .Where(j => !(authAvailable && string.Equals(j, AttackCatalog.SshJail, StringComparison.OrdinalIgnoreCase)))
                .Where(j => recidiveBanned || !string.Equals(j, AttackCatalog.RecidiveJail, StringComparison.OrdinalIgnoreCase))
                .Select(AttackCatalog.FromJail));
            if (sshBanned || failures.Count >= policy.FailuresBeforeLogin)
                types.Add(AttackType.SshBruteForce);
            if (campaignMembers.Contains(byIp.Key)) { types.Remove(AttackType.SshBruteForce); types.Add(AttackType.DistributedSshBruteForce); }
            if (suspicious[byIp.Key].Any(s => s.Reason == "after-failures")) types.Add(AttackType.LoginAfterFailures);

            var attempts = failures.Count + found.Count;
            var logins = events.Count(e => e.Kind == LogEventKind.AcceptedLogin);
            // Nothing hostile: only logins, or a user who mistyped once and then got in.
            if (types.Count == 0 && !suspicious[byIp.Key].Any() && (attempts == 0 || logins > 0)) continue;

            var bans = events.Count(e => e.Kind == LogEventKind.Ban);
            var severity = Grade(types, suspicious[byIp.Key].ToList(), bans, attempts);

            reports.Add(new IpReport(
                byIp.Key,
                geo.Locate(byIp.Key),
                severity.ToString(),
                types.Order().Select(t => t.ToString()).ToList(),
                attempts,
                bans,
                banned.Contains(byIp.Key),
                jails,
                failures.Where(e => e.User is not null).GroupBy(e => e.User!).Select(g => new UserCount(g.Key, g.Count()))
                    .OrderByDescending(u => u.Attempts).ThenBy(u => u.User, StringComparer.Ordinal).Take(5).ToList(),
                logins,
                events.Min(e => e.Time),
                events.Max(e => e.Time)));
        }

        return reports
            .OrderByDescending(r => Enum.Parse<Severity>(r.Severity))
            .ThenByDescending(r => r.Attempts)
            .ThenBy(r => r.Ip, StringComparer.Ordinal)
            .ToList();
    }

    private HashSet<string> CampaignMembers(IReadOnlyList<LogEvent> period, IReadOnlySet<string> bannedInPeriod)
    {
        var campaigns = Campaigns(period, bannedInPeriod).Select(c => c.User).ToHashSet(StringComparer.Ordinal);
        if (campaigns.Count == 0) return [];
        var failures = period.Where(e => e.Kind == LogEventKind.FailedLogin && e.User is not null).ToList();
        var usersByIp = failures.GroupBy(e => e.SourceIp).ToDictionary(g => g.Key, g => g.Select(e => e.User!).Distinct().ToList());
        return usersByIp
            .Where(kv => kv.Value.Count == 1 && campaigns.Contains(kv.Value[0]) && failures.Count(e => e.SourceIp == kv.Key) <= policy.CampaignMaxPerIp)
            .Select(kv => kv.Key)
            .ToHashSet();
    }

    private Severity Grade(HashSet<AttackType> types, List<SuspiciousLogin> suspicious, int bans, int attempts)
    {
        if (types.Contains(AttackType.LoginAfterFailures)) return Severity.Critical;
        if (types.Contains(AttackType.RepeatOffender) || suspicious.Count > 0) return Severity.High;
        if (bans > 0 || attempts >= policy.MediumAttempts || types.Contains(AttackType.DistributedSshBruteForce)
            || types.Contains(AttackType.RequestFlood) || types.Contains(AttackType.WebLoginBruteForce))
            return Severity.Medium;
        return Severity.Low;
    }
}
