using System.ComponentModel;
using ModelContextProtocol.Server;
using XrCopilotLab.Intrusion.Mcp.Core.Queries;

namespace XrCopilotLab.Intrusion.Mcp.Server.Tools;

/// <summary>
/// The tools the agent sees. All read-only: they read the host's fail2ban and sshd logs (or the simulated host) and
/// never ban, unban or change anything. Every answer says whether the data is simulated.
/// </summary>
[McpServerToolType]
public sealed class IntrusionTools(IntrusionQueries queries, TimeProvider clock)
{
    private const string PeriodHelp = "Hours back from now. Default 24, max 720 (30 days). Ignored when since is given.";

    [McpServerTool(Name = "intrusion_status", ReadOnly = true),
     Description(
        "State of the protection on the host: which fail2ban jails are active, how many addresses each one is banning now, " +
        "bans and attempts in the last 24 hours, the time of the latest event. Call it first to know what the host watches.")]
    public StatusResult Status() => queries.Status(clock.GetUtcNow());

    [McpServerTool(Name = "intrusion_banned_ips", ReadOnly = true),
     Description(
        "The addresses fail2ban is banning right now, newest first, with the jail, the attack type, since when, and where " +
        "the address is (country, city, coordinates, network).")]
    public BannedResult BannedIps(
        [Description("Only this jail (sshd, nginx-http-auth, nginx-botsearch, nginx-limit-req, recidive…). Null = all.")] string? jail = null)
        => queries.Banned(clock.GetUtcNow(), jail);

    [McpServerTool(Name = "intrusion_attempts", ReadOnly = true),
     Description(
        "Intrusion attempts in a period, one row per source address, most serious first: attempts, bans, accounts tried, " +
        "attack types, severity (Low, Medium, High, Critical), location. Filter by jail, attack type or country.")]
    public AttemptsResult Attempts(
        [Description(PeriodHelp)] int? hours = null,
        [Description("Start of the period (ISO 8601). Null = now minus hours.")] DateTimeOffset? since = null,
        [Description("End of the period (ISO 8601). Null = now.")] DateTimeOffset? until = null,
        [Description("Only addresses seen by this fail2ban jail. Null = all.")] string? jail = null,
        [Description("Only this attack type: SshBruteForce, DistributedSshBruteForce, WebLoginBruteForce, WebVulnerabilityScan, RequestFlood, MailLoginBruteForce, RepeatOffender, LoginAfterFailures. Null = all.")] string? attackType = null,
        [Description("Only addresses in this country (ISO code, e.g. CN). Null = all.")] string? country = null,
        [Description("Max rows. Default 20, max 100.")] int top = 20)
    {
        var now = clock.GetUtcNow();
        return queries.Attempts(now, queries.Resolve(now, hours, since, until), jail, attackType, country, top);
    }

    [McpServerTool(Name = "intrusion_ip_detail", ReadOnly = true),
     Description(
        "Everything one address did in the period: the summary row, any suspicious login, and the timeline of its events " +
        "(failed and successful logins, fail2ban matches, bans and unbans), newest first, up to 200.")]
    public IpDetailResult IpDetail(
        [Description("The source address (IPv4 or IPv6).")] string ip,
        [Description(PeriodHelp)] int? hours = null,
        [Description("Start of the period (ISO 8601). Null = now minus hours.")] DateTimeOffset? since = null,
        [Description("End of the period (ISO 8601). Null = now.")] DateTimeOffset? until = null)
    {
        var now = clock.GetUtcNow();
        return queries.IpDetail(now, queries.Resolve(now, hours, since, until), ip.Trim());
    }

    [McpServerTool(Name = "intrusion_suspicious_logins", ReadOnly = true),
     Description(
        "Successful SSH logins a person should check: after repeated failures from the same address (possible compromise, " +
        "Critical) or from a country users are not expected to work from (High).")]
    public SuspiciousLoginsResult SuspiciousLogins(
        [Description(PeriodHelp)] int? hours = null,
        [Description("Start of the period (ISO 8601). Null = now minus hours.")] DateTimeOffset? since = null,
        [Description("End of the period (ISO 8601). Null = now.")] DateTimeOffset? until = null)
    {
        var now = clock.GetUtcNow();
        return queries.SuspiciousLogins(now, queries.Resolve(now, hours, since, until));
    }

    [McpServerTool(Name = "intrusion_summary", ReadOnly = true),
     Description(
        "The picture of a period in one call: totals, attempts by attack type and by country, the top attackers, distributed " +
        "campaigns (one account tried from many addresses, each under the ban threshold), suspicious logins, and map points " +
        "(latitude, longitude, severity) ready for a map. Use it for a report or a dashboard.")]
    public SummaryResult Summary(
        [Description(PeriodHelp)] int? hours = null,
        [Description("Start of the period (ISO 8601). Null = now minus hours.")] DateTimeOffset? since = null,
        [Description("End of the period (ISO 8601). Null = now.")] DateTimeOffset? until = null,
        [Description("Max top attackers. Default 10, max 100.")] int top = 10)
    {
        var now = clock.GetUtcNow();
        return queries.Summary(now, queries.Resolve(now, hours, since, until), top);
    }
}
