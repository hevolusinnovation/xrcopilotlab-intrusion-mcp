namespace XrCopilotLab.Intrusion.Mcp.Core.Models;

/// <summary>The kind of attack a source IP is making, as far as the logs can tell.</summary>
public enum AttackType
{
    /// <summary>Repeated SSH password or key failures from one IP.</summary>
    SshBruteForce,

    /// <summary>The same account tried from many IPs, each staying under the fail2ban threshold.</summary>
    DistributedSshBruteForce,

    /// <summary>Repeated failures on a web login (HTTP basic auth or a login form watched by fail2ban).</summary>
    WebLoginBruteForce,

    /// <summary>Requests for pages that do not exist on the site, looking for a known vulnerable application.</summary>
    WebVulnerabilityScan,

    /// <summary>Requests that carry an exploit: SQL injection, path traversal, command injection, Log4Shell, a known CVE.</summary>
    WebExploitAttempt,

    /// <summary>More requests than the web server's rate limit allows: an attempt to overload the site.</summary>
    RequestFlood,

    /// <summary>Repeated failures on a mail login (SMTP AUTH, IMAP, POP3).</summary>
    MailLoginBruteForce,

    /// <summary>Connections to many closed ports in a short time: mapping which services the host exposes.</summary>
    PortScan,

    /// <summary>Connections to the ports of industrial control protocols (Modbus, S7, IEC 104, DNP3, OPC UA…).</summary>
    IndustrialProtocolProbe,

    /// <summary>An IP that came back after being banned several times (fail2ban jail <c>recidive</c>).</summary>
    RepeatOffender,

    /// <summary>A successful SSH login from an IP that had failed several times just before: possible compromise.</summary>
    LoginAfterFailures,

    /// <summary>A fail2ban jail or CrowdSec scenario this server does not classify.</summary>
    Other,
}

/// <summary>How urgently a person should look at an IP.</summary>
public enum Severity
{
    Low,
    Medium,
    High,
    Critical,
}
