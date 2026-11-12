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

    // Signature families of the ET Open rules (https://rules.emergingthreats.net): the prefix says what the rule is about.
    private static readonly string[] ReputationPrefixes = ["ET DROP", "ET CINS", "ET COMPROMISED", "ET DSHIELD", "ET 3CORESEC", "ET TOR"];
    private static readonly string[] MalwarePrefixes = ["ET MALWARE", "ET TROJAN", "ET CNC", "ET C2", "ET COINMINER", "ET MOBILE_MALWARE"];
    private static readonly string[] IndustrialWords = ["MODBUS", "DNP3", "ENIP", "ETHERNET/IP", "CIP ", "S7", "IEC 104", "IEC-104", "BACNET", "SCADA", "ICS "];
    private static readonly string[] IndustrialProtocols = ["modbus", "dnp3", "enip", "cip", "s7comm", "iec104", "bacnet"];

    /// <summary>
    /// The attack type of a Suricata alert, from its signature (ET Open naming), its category and its direction. A
    /// malware signature on a connection the host opened is <see cref="AttackType.CommandAndControl"/>; the same
    /// signature coming in is an exploit attempt.
    /// </summary>
    public static AttackType FromIdsAlert(LogEvent alert)
    {
        var signature = (alert.Rule ?? "").ToUpperInvariant();
        var category = (alert.Detail ?? "").ToLowerInvariant();
        var protocol = (alert.Protocol ?? "").ToLowerInvariant();
        bool Starts(string[] prefixes) => prefixes.Any(p => signature.StartsWith(p, StringComparison.Ordinal));

        if (alert.Outbound && (Starts(MalwarePrefixes) || category.Contains("trojan", StringComparison.Ordinal)
                || category.Contains("command and control", StringComparison.Ordinal) || category.Contains("malware", StringComparison.Ordinal)))
            return AttackType.CommandAndControl;
        if (Starts(ReputationPrefixes)) return AttackType.KnownMaliciousSource;
        if (IndustrialProtocols.Contains(protocol) || IndustrialWords.Any(w => signature.Contains(w, StringComparison.Ordinal)))
            return AttackType.IndustrialProtocolCommand;
        if (signature.StartsWith("ET SCAN", StringComparison.Ordinal) || category.Contains("network scan", StringComparison.Ordinal))
            return AttackType.PortScan;
        if (signature.StartsWith("ET WEB_", StringComparison.Ordinal) || category.Contains("web application attack", StringComparison.Ordinal))
            return AttackType.WebExploitAttempt;
        if (category.Contains("denial of service", StringComparison.Ordinal)) return AttackType.RequestFlood;
        if (Starts(MalwarePrefixes) || category.Contains("trojan", StringComparison.Ordinal)) return AttackType.NetworkExploitAttempt;
        if (signature.StartsWith("ET EXPLOIT", StringComparison.Ordinal) || category.Contains("privilege gain", StringComparison.Ordinal)
            || category.Contains("executable code", StringComparison.Ordinal) || category.Contains("attack", StringComparison.Ordinal))
            // The same exploit carried by a web request (Log4Shell in a header) is a web exploit.
            return protocol is "http" or "http2" ? AttackType.WebExploitAttempt : AttackType.NetworkExploitAttempt;
        return AttackType.Other;
    }

    private static readonly string[] MinerNames = ["xmrig", "xmr-stak", "minerd", "cpuminer", "ethminer", "nbminer", "t-rex", "kdevtmpfsi", "kinsing"];

    /// <summary>
    /// The attack type of a Falco alert, from its rule name and its MITRE ATT&amp;CK tags (<c>mitre_credential_access</c>…).
    /// The rules of Falco's default set and the three of <c>install.sh --with falco</c> each land on one type.
    /// </summary>
    public static AttackType FromHostAlert(LogEvent alert)
    {
        var rule = (alert.Rule ?? "").ToLowerInvariant();
        var tags = (alert.Detail ?? "").ToLowerInvariant();
        var command = (alert.Command ?? "").ToLowerInvariant();
        bool Rule(params string[] words) => words.Any(w => rule.Contains(w, StringComparison.Ordinal));
        bool Tag(string tag) => tags.Split(',').Contains(tag, StringComparer.Ordinal);

        if (Rule("miner", "mining") || command.Contains("stratum+", StringComparison.Ordinal)
            || MinerNames.Any(m => command.StartsWith(m, StringComparison.Ordinal) || command.Contains("/" + m, StringComparison.Ordinal)))
            return AttackType.CryptoMining;
        if (Rule("clear log", "log files", "remove bulk data")) return AttackType.LogTampering;
        if (Tag("mitre_credential_access") || Rule("sensitive file", "private keys", "credentials", "shadow")) return AttackType.SensitiveFileAccess;
        if (Tag("mitre_persistence") || Rule("authorized keys", "authorized_keys", "account")) return AttackType.Persistence;
        if (Tag("mitre_privilege_escalation") || Rule("ptrace", "kernel module", "escape", "release_agent", "debugfs"))
            return AttackType.PrivilegeEscalation;
        return AttackType.SuspiciousExecution;
    }

    /// <summary>The types a host alert can have: what someone did once inside, not an attempt to get in.</summary>
    public static bool IsHostActivity(AttackType type) =>
        type is AttackType.SensitiveFileAccess or AttackType.SuspiciousExecution or AttackType.Persistence
            or AttackType.PrivilegeEscalation or AttackType.LogTampering or AttackType.CryptoMining;

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
        AttackType.NetworkExploitAttempt => "Network traffic carrying a known attack against a service (seen by the network IDS, Suricata).",
        AttackType.KnownMaliciousSource => "An address on a public list of known attackers (Suricata reputation signatures).",
        AttackType.IndustrialProtocolCommand => "Industrial protocol commands on the network (Modbus, DNP3, EtherNet/IP, S7): someone talking to a plant system.",
        AttackType.CommandAndControl => "The host itself connecting to a malware controller: it is probably compromised.",
        AttackType.SensitiveFileAccess => "Sensitive files read on the host: /etc/shadow, private keys, credentials (Falco).",
        AttackType.SuspiciousExecution => "A program run where it should not be: a shell started by the web server, a binary from /dev/shm, a reverse shell (Falco).",
        AttackType.Persistence => "A way back in left on the host: an SSH key added, an account created (Falco).",
        AttackType.PrivilegeEscalation => "An attempt to get more rights on the host: ptrace, a kernel module, a container escape (Falco).",
        AttackType.LogTampering => "Logs cleared or data removed on the host: someone covering their tracks (Falco).",
        AttackType.CryptoMining => "A crypto-currency miner running on the host (Falco).",
        _ => "A detector rule this server does not classify.",
    };
}
