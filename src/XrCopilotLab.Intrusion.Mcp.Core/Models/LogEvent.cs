namespace XrCopilotLab.Intrusion.Mcp.Core.Models;

/// <summary>What a log line says happened.</summary>
public enum LogEventKind
{
    /// <summary>fail2ban matched a failure of this IP in a jail (<c>[sshd] Found 203.0.113.7</c>).</summary>
    Found,

    /// <summary>fail2ban banned the IP in a jail.</summary>
    Ban,

    /// <summary>fail2ban lifted the ban.</summary>
    Unban,

    /// <summary>fail2ban restored a ban after a restart: the IP is still banned.</summary>
    RestoreBan,

    /// <summary>sshd refused a password or a key (<c>Failed password for … from …</c>).</summary>
    FailedLogin,

    /// <summary>sshd saw a user that does not exist (<c>Invalid user … from …</c>). The same attempt also logs a <see cref="FailedLogin"/>.</summary>
    InvalidUser,

    /// <summary>sshd let the user in (<c>Accepted password|publickey for … from …</c>).</summary>
    AcceptedLogin,

    /// <summary>The firewall (UFW) dropped a connection to a closed port (<c>[UFW BLOCK] … SRC=… DPT=…</c>).</summary>
    FirewallBlock,

    /// <summary>A web request that matches a known attack pattern (nginx access log). Ordinary requests are not kept.</summary>
    WebRequest,

    /// <summary>CrowdSec recognised a scenario from this IP (<c>Ip … performed 'crowdsecurity/ssh-bf'</c>).</summary>
    CrowdsecAlert,

    /// <summary>CrowdSec decided a remedy for this IP (<c>… : 4h ban on Ip …</c>).</summary>
    CrowdsecDecision,

    /// <summary>A Suricata signature matched traffic to or from this IP (<c>eve.json</c>, <c>event_type: alert</c>).</summary>
    IdsAlert,

    /// <summary>
    /// A Falco rule matched something a process did on the host (<c>events.json</c>): a sensitive file read, a shell
    /// from a web server, a log cleared. It has no address of its own: <see cref="LogEvent.SourceIp"/> is empty until
    /// the event is tied to the address that opened the session (<see cref="LogEvent.LinkedBy"/>).
    /// </summary>
    HostAlert,

    /// <summary>
    /// ModSecurity with the OWASP CRS found enough evidence in one web request to block it (audit log, rule 949110). In
    /// detection-only mode the request went through: it was an attack all the same, and the WAF saw its body too.
    /// </summary>
    WafAlert,
}

/// <summary>Which log the event comes from.</summary>
public enum LogOrigin
{
    Fail2ban,
    Auth,
    Firewall,
    WebAccess,
    Crowdsec,
    Suricata,
    Falco,
    ModSecurity,
}

/// <summary>
/// One parsed log line about a source IP. <see cref="Port"/> is the source port of an SSH attempt;
/// <see cref="TargetPort"/> the port a blocked connection was aimed at. <see cref="Rule"/> is the web attack pattern
/// or the CrowdSec scenario or the Suricata signature; <see cref="Detail"/> the CrowdSec remedy duration or the
/// Suricata category. A Suricata alert also carries its <see cref="SignatureId"/>, its <see cref="Priority"/> (1 high,
/// 2 medium) and whether the host itself opened the connection (<see cref="Outbound"/>). A Falco alert carries the
/// rule in <see cref="Rule"/>, its tags in <see cref="Detail"/>, the file in <see cref="Path"/>, the process in
/// <see cref="Command"/> and <see cref="Parent"/>, the account that logged in in <see cref="User"/>, and how it was tied
/// to an address in <see cref="LinkedBy"/> (<c>ssh-session</c>, <c>web-exploit</c>). A ModSecurity alert carries the
/// request in <see cref="Method"/>, <see cref="Path"/> and <see cref="Status"/>, the first CRS rule in <see cref="Rule"/>
/// and <see cref="SignatureId"/>, its attack families in <see cref="Detail"/> and the anomaly score in <see cref="Score"/>.
/// <see cref="User"/>, <see cref="Path"/>, <see cref="Command"/> and <see cref="Parent"/> are the attacker's text, cleaned by
/// <see cref="Parsing.UntrustedText"/>; <see cref="Injection"/> is the rule that text matched when it was written for an
/// AI reading the logs (a prompt injection), or null.
/// </summary>
public sealed record LogEvent(
    DateTimeOffset Time,
    LogEventKind Kind,
    LogOrigin Origin,
    string SourceIp,
    string? Jail = null,
    string? User = null,
    int? Port = null,
    string? Method = null,
    int? TargetPort = null,
    string? Protocol = null,
    string? Path = null,
    int? Status = null,
    string? Rule = null,
    string? Detail = null,
    int? SignatureId = null,
    int? Priority = null,
    bool Outbound = false,
    string? Command = null,
    string? Parent = null,
    string? LinkedBy = null,
    int? Score = null,
    string? Injection = null)
{
    public bool IsBanStart => Kind is LogEventKind.Ban or LogEventKind.RestoreBan;

    /// <summary>A host event not tied to any address yet.</summary>
    public bool HasAddress => SourceIp.Length > 0;

    /// <summary>The host whose log the line comes from: a collector holds the events of several hosts.</summary>
    public string? Host { get; init; }
}
