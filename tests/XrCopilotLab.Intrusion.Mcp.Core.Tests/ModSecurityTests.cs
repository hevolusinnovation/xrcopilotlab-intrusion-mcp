using XrCopilotLab.Intrusion.Mcp.Core.Analysis;
using XrCopilotLab.Intrusion.Mcp.Core.Geo;
using XrCopilotLab.Intrusion.Mcp.Core.Models;
using XrCopilotLab.Intrusion.Mcp.Core.Parsing;
using Xunit;

namespace XrCopilotLab.Intrusion.Mcp.Core.Tests;

public class ModSecurityParserTests
{
    private static readonly TimeZoneInfo Rome = TimeZoneInfo.FindSystemTimeZoneById("Europe/Rome");

    // As ModSecurity 3.0.12 with CRS 3.3.5 wrote it on Ubuntu 24.04 (install.sh --with modsecurity: JSON, parts AHZ),
    // for a command injection in the body of a POST. Shortened "match" fields.
    private const string PostInjection = """{"transaction":{"client_ip":"198.51.100.7","time_stamp":"Thu Nov 12 13:51:22 2026","server_id":"67f364cebd34299e82e176362a51a554ceefb809","client_port":43540,"host_ip":"10.30.0.15","host_port":80,"unique_id":"179449148264.508889","request":{"method":"POST","http_version":1.1,"uri":"/login"},"response":{"http_code":200},"producer":{"modsecurity":"ModSecurity v3.0.12 (Linux)","connector":"ModSecurity-nginx v1.0.3","secrules_engine":"DetectionOnly","components":["OWASP_CRS/3.3.5\""]},"messages":[{"message":"Host header is a numeric IP address","details":{"match":"…","reference":"o0,9v74,9","ruleId":"920350","file":"/usr/share/modsecurity-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf","lineNumber":"719","data":"10.30.0.15","severity":"4","ver":"OWASP_CRS/3.3.5","rev":"","tags":["application-multi","language-multi","platform-multi","attack-protocol","paranoia-level/1","OWASP_CRS","capec/1000/210/272","PCI/6.5.10"],"maturity":"0","accuracy":"0"}},{"message":"OS File Access Attempt","details":{"match":"…","ruleId":"930120","severity":"2","tags":["application-multi","language-multi","platform-multi","attack-lfi","paranoia-level/1","OWASP_CRS"]}},{"message":"Remote Command Execution: Unix Command Injection","details":{"match":"…","ruleId":"932100","data":"Matched Data: ;cat /etc/passwd found within ARGS:cmd: ;cat /etc/passwd","severity":"2","tags":["application-multi","language-shell","platform-unix","attack-rce","paranoia-level/1","OWASP_CRS"]}},{"message":"Inbound Anomaly Score Exceeded (Total Score: 18)","details":{"match":"…","ruleId":"949110","severity":"2","tags":["application-multi","language-multi","platform-multi","attack-generic"]}}]}}""";

    [Fact]
    public void Reads_an_attack_the_crs_would_have_blocked()
    {
        Assert.True(ModSecurityParser.TryParse(PostInjection, Rome, out var e));
        Assert.Equal((LogEventKind.WafAlert, LogOrigin.ModSecurity, "198.51.100.7", "POST", "/login", 200),
            (e!.Kind, e.Origin, e.SourceIp, e.Method, e.Path, e.Status));
        // The most telling family first: command injection before the file access it carried.
        Assert.Equal(("Remote Command Execution: Unix Command Injection", 932100, "command-injection,path-traversal", 18),
            (e.Rule, e.SignatureId, e.Detail, e.Score));
        // Local time, written without an offset: 13:51 in Rome in November is 12:51 UTC.
        Assert.Equal(new DateTimeOffset(2026, 11, 12, 12, 51, 22, TimeSpan.Zero), e.Time);
        Assert.Equal(AttackType.WebExploitAttempt, ModSecurityParser.TypeOf(e));
    }

    [Fact]
    public void A_scanner_user_agent_is_a_scan_not_an_exploit()
    {
        var line = """{"transaction":{"client_ip":"203.0.113.40","time_stamp":"Thu Nov  5 09:01:02 2026","request":{"method":"GET","uri":"/"},"response":{"http_code":200},"messages":[{"message":"Found User-Agent associated with security scanner","details":{"ruleId":"913100","severity":"2","tags":["attack-reputation-scanner"]}},{"message":"Host header is a numeric IP address","details":{"ruleId":"920350","severity":"4","tags":["attack-protocol"]}},{"message":"Inbound Anomaly Score Exceeded (Total Score: 8)","details":{"ruleId":"949110","severity":"2","tags":["attack-generic"]}}]}}""";
        Assert.True(ModSecurityParser.TryParse(line, Rome, out var e));
        Assert.Equal(("scanner-agent", 8), (e!.Detail, e.Score));
        Assert.Equal(new DateTimeOffset(2026, 11, 5, 9, 1, 2, TimeSpan.FromHours(1)), e.Time);
        Assert.Equal(AttackType.WebVulnerabilityScan, ModSecurityParser.TypeOf(e));
    }

    [Theory]
    // A warning alone (a bare IP in the Host header) does not reach the blocking score: not an attack.
    [InlineData("""{"transaction":{"client_ip":"192.0.2.10","time_stamp":"Thu Nov 12 13:51:22 2026","request":{"method":"GET","uri":"/"},"response":{"http_code":200},"messages":[{"message":"Host header is a numeric IP address","details":{"ruleId":"920350","severity":"4","tags":["attack-protocol"]}}]}}""")]
    [InlineData("""{"transaction":{"client_ip":"not-an-ip","time_stamp":"Thu Nov 12 13:51:22 2026","messages":[]}}""")]
    [InlineData("""ModSecurity: Warning. Matched "Operator `Rx' …""")]
    [InlineData("""{"transaction": broken""")]
    public void Skips_warnings_below_the_threshold_and_broken_lines(string line) =>
        Assert.False(ModSecurityParser.TryParse(line, Rome, out _));
}

public class WafAnalysisTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 12, 3, 0, 0, TimeSpan.FromHours(1));
    private readonly ThreatAnalyzer _analyzer = new(new IntrusionPolicy(), new NoGeoLocator());

    private static LogEvent Waf(int second, string ip, string families, int score = 15) =>
        new(T0.AddSeconds(second), LogEventKind.WafAlert, LogOrigin.ModSecurity, ip, Method: "POST", Path: "/contact.php", Status: 200,
            Rule: "SQL Injection Attack Detected via libinjection", Detail: families, SignatureId: 942100, Score: score);

    [Fact]
    public void An_injection_only_the_waf_saw_makes_a_high_report_with_its_findings()
    {
        var report = Assert.Single(_analyzer.Reports([Waf(0, "198.51.100.30", "sql-injection"), Waf(5, "198.51.100.30", "sql-injection", 20)], []));
        Assert.Equal(nameof(Severity.High), report.Severity);
        Assert.Equal([nameof(AttackType.WebExploitAttempt)], report.AttackTypes);
        Assert.Equal(2, report.Attempts);
        var finding = Assert.Single(report.WafFindings);
        Assert.Equal(("sql-injection", 942100, 2, 20, "POST /contact.php"), (finding.Family, finding.RuleId, finding.Requests, finding.MaxScore, finding.Example));
    }

    [Fact]
    public void The_same_request_in_the_access_log_and_the_waf_counts_once()
    {
        var events = new List<LogEvent>
        {
            new(T0, LogEventKind.WebRequest, LogOrigin.WebAccess, "203.0.113.9", Method: "GET", Path: "/?id=1' or '1'='1", Status: 200, Rule: "sql-injection"),
            Waf(0, "203.0.113.9", "sql-injection"),
        };
        Assert.Equal(1, Assert.Single(_analyzer.Reports(events, [])).Attempts);
    }

    [Fact]
    public void A_shell_below_the_web_server_goes_to_the_address_the_waf_caught()
    {
        var events = new List<LogEvent>
        {
            Waf(0, "203.0.113.9", "command-injection"),
            new(T0.AddMinutes(1), LogEventKind.HostAlert, LogOrigin.Falco, "", User: "www-data", Rule: "Run shell untrusted",
                Detail: "host,mitre_execution", Priority: 3, Command: "sh -c id", Parent: "php-fpm8.3 < nginx"),
        };
        var alert = HostAlertLinker.Link(events).Single(e => e.Kind == LogEventKind.HostAlert);
        Assert.Equal(("203.0.113.9", "web-exploit"), (alert.SourceIp, alert.LinkedBy));
    }
}
