using XrCopilotLab.Intrusion.Mcp.Core.Geo;

namespace XrCopilotLab.Intrusion.Mcp.Core.Queries;

// What the tools return. Enums travel as their names (strings), so the JSON reads the same whatever the serializer.

public sealed record Period(DateTimeOffset From, DateTimeOffset To);

public sealed record UserCount(string User, int Attempts);

/// <summary>A closed port somebody tried: which service it is, how many blocked connections, from how many addresses.</summary>
public sealed record PortCount(int Port, string? Service, int Blocks, int Addresses);

/// <summary>A web attack pattern seen in the requests of an address, with one example path.</summary>
public sealed record WebProbe(string Rule, string AttackType, int Requests, string Example);

/// <summary>A Suricata signature that matched the traffic of an address. <c>Outbound</c>: the host itself opened the
/// connection (a compromised host calling its controller). <c>Priority</c>: 1 high, 2 medium.</summary>
public sealed record IdsSignature(string Signature, int? SignatureId, string? Category, string AttackType, int Priority, int Alerts, bool Outbound);

/// <summary>Everything one source address did in the period.</summary>
public sealed record IpReport(
    string Ip,
    GeoLocation Location,
    string Severity,
    IReadOnlyList<string> AttackTypes,
    int Attempts,
    int Bans,
    bool CurrentlyBanned,
    IReadOnlyList<string> Jails,
    IReadOnlyList<UserCount> UsersTried,
    int SuccessfulLogins,
    int FirewallBlocks,
    IReadOnlyList<PortCount> PortsProbed,
    IReadOnlyList<WebProbe> WebProbes,
    IReadOnlyList<string> CrowdsecScenarios,
    IReadOnlyList<IdsSignature> IdsSignatures,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen);

public sealed record SuspiciousLogin(
    DateTimeOffset Time,
    string Ip,
    string User,
    string? Method,
    GeoLocation Location,
    int FailuresBefore,
    string Reason,
    string Severity);

/// <summary>One account tried from many addresses, each under the ban threshold.</summary>
public sealed record Campaign(
    string User,
    int Addresses,
    int Attempts,
    int BannedAddresses,
    IReadOnlyList<string> Countries,
    DateTimeOffset First,
    DateTimeOffset Last);

public sealed record MapPoint(
    string Ip,
    double Latitude,
    double Longitude,
    string? Country,
    string? City,
    string Severity,
    int Attempts,
    IReadOnlyList<string> AttackTypes);

public sealed record AttackTypeCount(string Type, string Description, int Addresses, int Attempts);

public sealed record CountryCount(string? CountryCode, string? Country, int Addresses, int Attempts);

public sealed record JailStatus(string Jail, string AttackType, int CurrentlyBanned, int BansLast24h, int AttemptsLast24h);

/// <summary>One log the server reads: fail2ban, sshd, ufw, nginx, crowdsec, suricata.</summary>
public sealed record DetectorStatus(string Detector, int EventsLast24h, DateTimeOffset? LatestEvent);

public sealed record StatusResult(
    string Host,
    bool Simulated,
    IReadOnlyList<string> Sources,
    DateTimeOffset Now,
    DateTimeOffset? OldestEvent,
    DateTimeOffset? LatestEvent,
    int EventsLast24h,
    int CurrentlyBanned,
    IReadOnlyList<DetectorStatus> Detectors,
    IReadOnlyList<JailStatus> Jails,
    string? GeoAttribution);

public sealed record BannedIp(string Ip, string Jail, string AttackType, DateTimeOffset Since, GeoLocation Location);

public sealed record BannedResult(string Host, bool Simulated, DateTimeOffset Now, int Count, IReadOnlyList<BannedIp> Banned, string? GeoAttribution);

public sealed record AttemptsResult(string Host, bool Simulated, Period Period, int Addresses, IReadOnlyList<IpReport> Top, string? GeoAttribution);

/// <summary>One event of an address: <c>Port</c> is its source port on SSH, <c>TargetPort</c> the closed port it tried,
/// <c>Rule</c> the web pattern, CrowdSec scenario or Suricata signature; <c>Outbound</c> a connection the host opened.</summary>
public sealed record TimelineEntry(DateTimeOffset Time, string Kind, string Origin, string? Jail, string? User, int? Port, string? Method,
    int? TargetPort, string? Path, int? Status, string? Rule, string? Detail, bool Outbound = false);

public sealed record IpDetailResult(string Host, bool Simulated, Period Period, IpReport? Report, IReadOnlyList<SuspiciousLogin> SuspiciousLogins,
    int TimelineCount, IReadOnlyList<TimelineEntry> Timeline, string? GeoAttribution);

public sealed record SuspiciousLoginsResult(string Host, bool Simulated, Period Period, int SuccessfulLogins, IReadOnlyList<SuspiciousLogin> Suspicious, string? GeoAttribution);

public sealed record SummaryTotals(int Attempts, int Addresses, int Bans, int CurrentlyBanned, int SuccessfulLogins, int SuspiciousLogins,
    int FirewallBlocks, int WebAttackRequests, int CrowdsecAlerts, int IdsAlerts);

public sealed record SummaryResult(
    string Host,
    bool Simulated,
    Period Period,
    SummaryTotals Totals,
    IReadOnlyList<AttackTypeCount> ByAttackType,
    IReadOnlyList<CountryCount> ByCountry,
    IReadOnlyList<PortCount> TopTargetedPorts,
    IReadOnlyList<IpReport> TopAttackers,
    IReadOnlyList<Campaign> Campaigns,
    IReadOnlyList<SuspiciousLogin> SuspiciousLogins,
    IReadOnlyList<MapPoint> MapPoints,
    string? GeoAttribution);
