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

    /// <summary>A network IDS signature on an attack against a service other than the web (SMB, SSH, a database, a known CVE).</summary>
    NetworkExploitAttempt,

    /// <summary>The source is on a public list of known malicious addresses (Suricata ET DROP / CINS / Dshield signatures).</summary>
    KnownMaliciousSource,

    /// <summary>Commands of an industrial protocol seen on the network (Modbus, DNP3, EtherNet/IP, S7): someone talking to a plant system.</summary>
    IndustrialProtocolCommand,

    /// <summary>The host itself connecting to a malware controller: the strongest sign that it has been compromised.</summary>
    CommandAndControl,

    /// <summary>Sensitive files read on the host: <c>/etc/shadow</c>, private keys, credentials (Falco).</summary>
    SensitiveFileAccess,

    /// <summary>A program run where it should not be: a shell started by the web server, a binary from <c>/dev/shm</c>, a reverse shell (Falco).</summary>
    SuspiciousExecution,

    /// <summary>A way back in left on the host: an SSH key added, an account created (Falco).</summary>
    Persistence,

    /// <summary>An attempt to get more rights: ptrace on another process, a kernel module loaded, a container escape (Falco).</summary>
    PrivilegeEscalation,

    /// <summary>Logs cleared or bulk data removed: covering tracks (Falco).</summary>
    LogTampering,

    /// <summary>A crypto-currency miner running on the host (Falco).</summary>
    CryptoMining,

    /// <summary>A fail2ban jail, CrowdSec scenario, Suricata signature or Falco rule this server does not classify.</summary>
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
