using XrCopilotLab.Intrusion.Mcp.Core.Geo;
using XrCopilotLab.Intrusion.Mcp.Core.Models;
using XrCopilotLab.Intrusion.Mcp.Core.Parsing;
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
        // A host alert not tied to any address is the host's: it is in HostAlerts, not in an attacker's row.
        foreach (var byIp in period.Where(e => e.HasAddress).GroupBy(e => e.SourceIp))
        {
            var ip = byIp.Key;
            var events = byIp.ToList();
            var failures = events.Where(e => e.Kind == LogEventKind.FailedLogin).ToList();
            var found = events.Where(e => e.Kind == LogEventKind.Found && AttackCatalog.CountsAttempts(e.Jail!)).ToList();
            var web = events.Where(e => e.Kind == LogEventKind.WebRequest).ToList();
            var blocks = events.Where(e => e.Kind == LogEventKind.FirewallBlock).ToList();
            var alerts = events.Where(e => e.Kind == LogEventKind.CrowdsecAlert).ToList();
            var ids = events.Where(e => e.Kind == LogEventKind.IdsAlert).ToList();
            var host = events.Where(e => e.Kind == LogEventKind.HostAlert).ToList();
            var waf = events.Where(e => e.Kind == LogEventKind.WafAlert).ToList();
            var jails = events.Where(e => e.Jail is not null).Select(e => e.Jail!).Distinct().Order().ToList();

            // One attempt, one count: sshd from auth.log when it is there, web from whichever of fail2ban, nginx and the WAF
            // saw more (they see the same requests; the WAF also sees the bodies).
            var sshFound = found.Count(e => IsSsh(e.Jail));
            var webFound = found.Count(e => AttackCatalog.IsWeb(AttackCatalog.FromJail(e.Jail!)));
            var otherFound = found.Count - sshFound - webFound;
            var attempts = (authAvailable ? failures.Count : sshFound) + Math.Max(webFound, Math.Max(web.Count, waf.Count)) + otherFound;

            // With auth.log, one sshd match is a mistyped password: brute force takes repeated failures or a ban.
            var sshBanned = events.Any(e => e.IsBanStart && IsSsh(e.Jail));
            // recidive writes a Found for every ban of every jail: an address is a repeat offender only once recidive bans it.
            var recidiveBanned = events.Any(e => e.IsBanStart && IsRecidive(e.Jail)) || currentBans.Any(b => b.Ip == ip && IsRecidive(b.Jail));
            var types = new HashSet<AttackType>(jails
                .Where(j => !(authAvailable && IsSsh(j)))
                .Where(j => recidiveBanned || !IsRecidive(j))
                .Select(AttackCatalog.FromJail));
            var logins = events.Count(e => e.Kind == LogEventKind.AcceptedLogin);
            // A stranger trying passwords is brute force even with one try; a user who got in after a typo is not.
            if (sshBanned || failures.Count >= policy.FailuresBeforeLogin || (failures.Count > 0 && logins == 0)) types.Add(AttackType.SshBruteForce);
            foreach (var r in web) types.Add(WebProbeRules.TypeOf(r.Rule!));
            foreach (var a in alerts) types.Add(AttackCatalog.FromScenario(a.Rule!));
            foreach (var a in ids) types.Add(AttackCatalog.FromIdsAlert(a));
            foreach (var a in host) types.Add(AttackCatalog.FromHostAlert(a));
            foreach (var a in waf) types.Add(ModSecurityParser.TypeOf(a));

            var ports = blocks.Where(b => b.TargetPort is not null).GroupBy(b => b.TargetPort!.Value).ToList();
            if (ports.Count >= policy.PortScanMinPorts) types.Add(AttackType.PortScan);
            if (ports.Any(p => AttackCatalog.IndustrialPorts.ContainsKey(p.Key))) types.Add(AttackType.IndustrialProtocolProbe);

            if (campaignMembers.Contains(ip)) { types.Remove(AttackType.SshBruteForce); types.Add(AttackType.DistributedSshBruteForce); }
            if (suspicious[ip].Any(s => s.Reason == "after-failures")) types.Add(AttackType.LoginAfterFailures);
            if (types.Count > 1) types.Remove(AttackType.Other);

            // Nothing hostile: a few blocked packets, only logins, or a user who mistyped once and then got in.
            if (types.Count == 0 && !suspicious[ip].Any() && (attempts == 0 || logins > 0)) continue;

            var bans = events.Count(e => e.Kind == LogEventKind.Ban);
            var severity = Grade(types, suspicious[ip].ToList(), bans, attempts, alerts.Count, ids, host);

            reports.Add(new IpReport(
                ip,
                geo.Locate(ip),
                severity.ToString(),
                types.Order().Select(t => t.ToString()).ToList(),
                attempts,
                bans,
                banned.Contains(ip),
                jails,
                failures.Where(e => e.User is not null).GroupBy(e => e.User!).Select(g => new UserCount(g.Key, g.Count()))
                    .OrderByDescending(u => u.Attempts).ThenBy(u => u.User, StringComparer.Ordinal).Take(5).ToList(),
                logins,
                blocks.Count,
                ports.Select(p => new PortCount(p.Key, AttackCatalog.ServiceOf(p.Key), p.Count(), 1))
                    .OrderByDescending(p => AttackCatalog.IndustrialPorts.ContainsKey(p.Port)).ThenByDescending(p => p.Blocks).ThenBy(p => p.Port)
                    .Take(10).ToList(),
                web.GroupBy(r => r.Rule!).Select(g => new WebProbe(g.Key, WebProbeRules.TypeOf(g.Key).ToString(), g.Count(), g.First().Path ?? ""))
                    .OrderByDescending(p => p.Requests).Take(5).ToList(),
                alerts.Select(a => a.Rule!).Distinct().Order(StringComparer.Ordinal).ToList(),
                ids.GroupBy(a => a.Rule!)
                    .Select(g => new IdsSignature(g.Key, g.First().SignatureId, g.First().Detail, AttackCatalog.FromIdsAlert(g.First()).ToString(),
                        g.Min(a => a.Priority ?? SuricataPriorityLow), g.Count(), g.First().Outbound))
                    .OrderBy(x => x.Priority).ThenByDescending(x => x.Alerts).Take(10).ToList(),
                host.GroupBy(a => a.Rule!)
                    .Select(g => new HostActivity(g.Key, AttackCatalog.FromHostAlert(g.First()).ToString(), g.Min(a => a.Priority ?? FalcoParser.MaxPriority),
                        g.Count(), g.First().User, g.First().Command, g.First().Path, g.First().LinkedBy ?? ""))
                    .OrderBy(x => x.Priority).ThenByDescending(x => x.Alerts).Take(10).ToList(),
                waf.GroupBy(ModSecurityParser.FamilyOf)
                    .Select(g => new WafFinding(g.Key, ModSecurityParser.TypeOf(g.First()).ToString(), g.First().SignatureId, g.First().Rule!, g.Count(),
                        g.Max(a => a.Score ?? 0), $"{g.First().Method} {g.First().Path}"))
                    .OrderByDescending(x => x.Requests).Take(10).ToList(),
                events.Min(e => e.Time),
                events.Max(e => e.Time)));
        }

        return reports
            .OrderByDescending(r => Enum.Parse<Severity>(r.Severity))
            .ThenByDescending(r => r.Attempts)
            .ThenBy(r => r.Ip, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>
    /// How urgent one host alert is on its own: Critical for Falco's critical rules, a miner, cleared logs, or anything
    /// done below the web server after an exploit; High for the rest of what Falco warns about; Medium for a notice
    /// nobody can be tied to.
    /// </summary>
    public static Severity HostAlertSeverity(LogEvent alert)
    {
        var type = AttackCatalog.FromHostAlert(alert);
        if (alert.Priority == 1 || type is AttackType.CryptoMining or AttackType.LogTampering || alert.LinkedBy == "web-exploit") return Severity.Critical;
        return alert.Priority <= 2 || alert.HasAddress ? Severity.High : Severity.Medium;
    }

    public static HostAlert ToHostAlert(LogEvent e) =>
        new(e.Time, e.Rule!, AttackCatalog.FromHostAlert(e).ToString(), HostAlertSeverity(e).ToString(), e.Priority ?? FalcoParser.MaxPriority,
            e.User, e.Command, e.Parent, e.Path, e.HasAddress ? e.SourceIp : null, e.LinkedBy, e.Detail);

    /// <summary>The closed ports the whole period's traffic went for, industrial ports first.</summary>
    public static IReadOnlyList<PortCount> TargetedPorts(IReadOnlyList<LogEvent> period, int top) =>
        period.Where(e => e.Kind == LogEventKind.FirewallBlock && e.TargetPort is not null)
            .GroupBy(e => e.TargetPort!.Value)
            .Select(g => new PortCount(g.Key, AttackCatalog.ServiceOf(g.Key), g.Count(), g.Select(e => e.SourceIp).Distinct().Count()))
            .OrderByDescending(p => p.Addresses).ThenByDescending(p => p.Blocks).ThenBy(p => p.Port)
            .Take(top)
            .ToList();

    private static bool IsSsh(string? jail) => string.Equals(jail, AttackCatalog.SshJail, StringComparison.OrdinalIgnoreCase);

    private static bool IsRecidive(string? jail) => string.Equals(jail, AttackCatalog.RecidiveJail, StringComparison.OrdinalIgnoreCase);

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

    private const int SuricataPriorityLow = 3;

    private Severity Grade(HashSet<AttackType> types, List<SuspiciousLogin> suspicious, int bans, int attempts, int crowdsecAlerts, List<LogEvent> ids,
        List<LogEvent> host)
    {
        if (types.Contains(AttackType.LoginAfterFailures) || types.Contains(AttackType.CommandAndControl)) return Severity.Critical;
        // What someone did once inside: critical on its own (a miner, cleared logs, a web shell), or from an address that
        // was attacking too. From an ordinary login (an administrator reading /etc/shadow) it is for a person to check.
        if (host.Count > 0)
        {
            if (host.Any(a => HostAlertSeverity(a) == Severity.Critical) || types.Any(t => !AttackCatalog.IsHostActivity(t) && t != AttackType.Other)
                || suspicious.Count > 0)
                return Severity.Critical;
            return Severity.High;
        }
        if (types.Contains(AttackType.RepeatOffender) || types.Contains(AttackType.IndustrialProtocolProbe)
            || types.Contains(AttackType.WebExploitAttempt) || types.Contains(AttackType.IndustrialProtocolCommand) || suspicious.Count > 0
            // A high-priority IDS signature on an attack: Suricata saw the exploit itself, not a symptom of it.
            || ids.Any(a => a.Priority == 1 && AttackCatalog.FromIdsAlert(a) == AttackType.NetworkExploitAttempt))
            return Severity.High;
        if (bans > 0 || crowdsecAlerts > 0 || ids.Count > 0 || attempts >= policy.MediumAttempts || types.Contains(AttackType.DistributedSshBruteForce)
            || types.Contains(AttackType.RequestFlood) || types.Contains(AttackType.WebLoginBruteForce) || types.Contains(AttackType.PortScan))
            return Severity.Medium;
        return Severity.Low;
    }
}
