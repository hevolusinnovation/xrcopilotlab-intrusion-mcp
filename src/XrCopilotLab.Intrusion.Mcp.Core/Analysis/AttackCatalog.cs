using XrCopilotLab.Intrusion.Mcp.Core.Models;

namespace XrCopilotLab.Intrusion.Mcp.Core.Analysis;

/// <summary>
/// The attack type each detector reports: fail2ban jails (names of the filters in <c>/etc/fail2ban/filter.d</c>),
/// CrowdSec scenarios (<c>crowdsecurity/…</c> from the hub), firewall ports. Unknown names are <see cref="AttackType.Other"/>.
/// </summary>
public static class AttackCatalog
{
    public const string SshJail = "sshd";
    public const string RecidiveJail = "recidive";

    /// <summary>Ports of industrial control protocols: nobody on the internet has a reason to reach them.</summary>
    public static readonly IReadOnlyDictionary<int, string> IndustrialPorts = new Dictionary<int, string>
    {
        [102] = "Siemens S7 (ISO-TSAP)",
        [502] = "Modbus/TCP",
        [1911] = "Niagara Fox",
        [2404] = "IEC 60870-5-104",
        [4840] = "OPC UA",
        [20000] = "DNP3",
        [44818] = "EtherNet/IP",
        [47808] = "BACnet",
    };

    private static readonly Dictionary<int, string> CommonPorts = new()
    {
        [21] = "FTP", [22] = "SSH", [23] = "Telnet", [25] = "SMTP", [53] = "DNS", [80] = "HTTP", [110] = "POP3",
        [135] = "MS RPC", [139] = "NetBIOS", [143] = "IMAP", [443] = "HTTPS", [445] = "SMB", [1433] = "SQL Server",
        [1883] = "MQTT", [2323] = "Telnet (alt)", [3306] = "MySQL", [3389] = "RDP", [5432] = "PostgreSQL",
        [5555] = "Android ADB", [5900] = "VNC", [6379] = "Redis", [8080] = "HTTP (alt)", [8443] = "HTTPS (alt)",
        [9200] = "Elasticsearch", [11211] = "Memcached", [27017] = "MongoDB",
    };

    public static string? ServiceOf(int port) =>
        IndustrialPorts.TryGetValue(port, out var ics) ? ics : CommonPorts.TryGetValue(port, out var s) ? s : null;

    public static AttackType FromJail(string jail) => jail.Trim().ToLowerInvariant() switch
    {
        "sshd" or "ssh" or "sshd-ddos" or "dropbear" => AttackType.SshBruteForce,
        "nginx-http-auth" or "apache-auth" or "lighttpd-auth" or "wordpress" or "drupal-auth" or "nextcloud" or "gitlab"
            or "grafana" or "phpmyadmin-syslog" or "roundcube-auth" => AttackType.WebLoginBruteForce,
        "nginx-botsearch" or "apache-botsearch" or "apache-noscript" or "apache-overflows" or "apache-nohome"
            or "apache-badbots" or "apache-fakegooglebot" or "php-url-fopen" or "nginx-bad-request" => AttackType.WebVulnerabilityScan,
        "nginx-limit-req" or "apache-modsecurity" => AttackType.RequestFlood,
        "postfix" or "postfix-sasl" or "dovecot" or "courier-auth" or "exim" or "sasl" => AttackType.MailLoginBruteForce,
        "portscan" or "ufw-portscan" => AttackType.PortScan,
        "recidive" => AttackType.RepeatOffender,
        _ => AttackType.Other,
    };

    /// <summary>The attack type of a CrowdSec scenario, from its name (<c>crowdsecurity/http-sqli-probing</c>).</summary>
    public static AttackType FromScenario(string scenario)
    {
        var s = scenario.ToLowerInvariant();
        if (s.Contains("ssh", StringComparison.Ordinal) && s.Contains("bf", StringComparison.Ordinal)) return AttackType.SshBruteForce;
        if (s.Contains("scan-multi_ports", StringComparison.Ordinal) || s.Contains("portscan", StringComparison.Ordinal)) return AttackType.PortScan;
        if (s.Contains("cve", StringComparison.Ordinal) || s.Contains("sqli", StringComparison.Ordinal) || s.Contains("xss", StringComparison.Ordinal)
            || s.Contains("path-traversal", StringComparison.Ordinal) || s.Contains("log4j", StringComparison.Ordinal) || s.Contains("vpatch", StringComparison.Ordinal))
            return AttackType.WebExploitAttempt;
        if (s.Contains("http", StringComparison.Ordinal) && s.Contains("bf", StringComparison.Ordinal)) return AttackType.WebLoginBruteForce;
        if (s.Contains("probing", StringComparison.Ordinal) || s.Contains("sensitive-files", StringComparison.Ordinal)
            || s.Contains("bad-user-agent", StringComparison.Ordinal) || s.Contains("backdoors", StringComparison.Ordinal)
            || s.Contains("crawl", StringComparison.Ordinal) || s.Contains("admin-interface", StringComparison.Ordinal))
            return AttackType.WebVulnerabilityScan;
        if (s.Contains("postfix", StringComparison.Ordinal) || s.Contains("dovecot", StringComparison.Ordinal)) return AttackType.MailLoginBruteForce;
        return AttackType.Other;
    }

    /// <summary>Whether the jail's <c>Found</c> lines are attempts against a service (the recidive jail counts bans, not attempts).</summary>
    public static bool CountsAttempts(string jail) => !string.Equals(jail, RecidiveJail, StringComparison.OrdinalIgnoreCase);

    /// <summary>Web jails: their Found lines and the nginx access log describe the same requests.</summary>
    public static bool IsWeb(AttackType type) =>
        type is AttackType.WebLoginBruteForce or AttackType.WebVulnerabilityScan or AttackType.WebExploitAttempt or AttackType.RequestFlood;

    public static string Describe(AttackType type) => type switch
    {
        AttackType.SshBruteForce => "Repeated SSH login failures from one address.",
        AttackType.DistributedSshBruteForce => "The same SSH account tried from many addresses, each one staying under the ban threshold.",
        AttackType.WebLoginBruteForce => "Repeated failures on a web login.",
        AttackType.WebVulnerabilityScan => "Requests for pages that do not exist, looking for a vulnerable application.",
        AttackType.WebExploitAttempt => "Requests carrying an exploit: SQL injection, path traversal, command injection, Log4Shell, a known CVE.",
        AttackType.RequestFlood => "More requests than the rate limit allows: an attempt to overload the site.",
        AttackType.MailLoginBruteForce => "Repeated failures on a mail login.",
        AttackType.PortScan => "Connections to many closed ports in a short time: mapping the services the host exposes.",
        AttackType.IndustrialProtocolProbe => "Connections to industrial control ports (Modbus, S7, IEC 104, DNP3, OPC UA…): looking for plant systems.",
        AttackType.RepeatOffender => "An address banned several times that keeps coming back.",
        AttackType.LoginAfterFailures => "A successful SSH login right after repeated failures from the same address: possible compromise.",
        _ => "A detector rule this server does not classify.",
    };
}
