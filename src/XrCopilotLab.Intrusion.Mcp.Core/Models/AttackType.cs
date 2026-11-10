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

    /// <summary>More requests than the web server's rate limit allows: an attempt to overload the site.</summary>
    RequestFlood,

    /// <summary>Repeated failures on a mail login (SMTP AUTH, IMAP, POP3).</summary>
    MailLoginBruteForce,

    /// <summary>An IP that came back after being banned several times (fail2ban jail <c>recidive</c>).</summary>
    RepeatOffender,

    /// <summary>A successful SSH login from an IP that had failed several times just before: possible compromise.</summary>
    LoginAfterFailures,

    /// <summary>A fail2ban jail this server does not know.</summary>
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
