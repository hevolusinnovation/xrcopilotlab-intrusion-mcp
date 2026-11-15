using XrCopilotLab.Intrusion.Mcp.Core.Analysis;
using XrCopilotLab.Intrusion.Mcp.Core.Geo;
using XrCopilotLab.Intrusion.Mcp.Core.Models;
using XrCopilotLab.Intrusion.Mcp.Core.Parsing;
using Xunit;

namespace XrCopilotLab.Intrusion.Mcp.Core.Tests;

public class FalcoParserTests
{
    // As Falco 0.45 writes it, with the fields install.sh --with falco appends (user.loginname, proc.aname[2..4]).
    private const string Shadow = """{"hostname":"lab-01","output":"11:35:53.410250641: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow","output_fields":{"container.id":"host","evt.time":1794483353410250641,"evt.type":"openat","fd.name":"/etc/shadow","proc.aname[2]":"bash","proc.aname[3]":"sshd","proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.name":"cat","proc.pname":"sudo","user.loginname":"operatore","user.loginuid":1001,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-11-12T11:35:53.410250641Z"}""";

    [Fact]
    public void Reads_an_alert_with_the_account_that_logged_in()
    {
        Assert.True(FalcoParser.TryParse(Shadow, out var e));
        Assert.Equal((LogEventKind.HostAlert, LogOrigin.Falco, "", "operatore", "/etc/shadow", 2, "cat /etc/shadow", "sudo < bash < sshd"),
            (e!.Kind, e.Origin, e.SourceIp, e.User, e.Path, e.Priority, e.Command, e.Parent));
        Assert.Equal(new DateTimeOffset(2026, 11, 12, 11, 35, 53, TimeSpan.Zero).AddTicks(4102506), e.Time);
        Assert.False(e.HasAddress);
        Assert.Equal(AttackType.SensitiveFileAccess, AttackCatalog.FromHostAlert(e));
    }

    [Fact]
    public void A_process_of_an_ssh_session_carries_the_client_address()
    {
        var line = Shadow.Replace("\"user.loginname\":\"operatore\"", "\"user.loginname\":\"<NA>\",\"proc.env[SSH_CLIENT]\":\"198.51.100.213 39183 22\",\"proc.env[SUDO_USER]\":\"\"", StringComparison.Ordinal)
            .Replace("\"user.name\":\"root\"", "\"user.name\":\"operatore\"", StringComparison.Ordinal);
        Assert.True(FalcoParser.TryParse(line, out var e));
        Assert.Equal(("198.51.100.213", "ssh-session", "operatore"), (e!.SourceIp, e.LinkedBy, e.User));
    }

    [Fact]
    public void Below_sudo_the_account_is_the_one_that_ran_sudo()
    {
        // A kernel without audit (a container, some cloud kernels) gives no loginname: SUDO_USER says who it was.
        var line = Shadow.Replace("\"user.loginname\":\"operatore\"", "\"user.loginname\":\"<NA>\",\"proc.env[SSH_CLIENT]\":\"\",\"proc.env[SUDO_USER]\":\"operatore\"", StringComparison.Ordinal);
        Assert.True(FalcoParser.TryParse(line, out var e));
        Assert.Equal(("", "operatore"), (e!.SourceIp, e.User));
    }

    [Fact]
    public void Without_a_login_the_account_is_the_process_owner()
    {
        var line = Shadow.Replace("\"user.loginname\":\"operatore\"", "\"user.loginname\":\"<NA>\"", StringComparison.Ordinal)
            .Replace("\"proc.pname\":\"sudo\"", "\"proc.pname\":\"<NA>\"", StringComparison.Ordinal);
        Assert.True(FalcoParser.TryParse(line, out var e));
        Assert.Equal(("root", null), (e!.User, e.Parent));
    }

    [Theory]
    [InlineData("""{"output":"x","priority":"Informational","rule":"System user interactive","time":"2026-11-12T11:35:53Z"}""")]
    [InlineData("""{"output":"x","priority":"Notice","rule":"Terminal shell in container","time":"2026-11-12T11:35:53Z"}""")]
    [InlineData("""Thu Nov 12 11:35:17 2026: Falco initialized with configuration files:""")]
    [InlineData("""{"output":"x","output_fields":{"proc.name":"Suricata-Main"},"priority":"Notice","rule":"Packet socket created in container","time":"2026-11-12T11:35:53Z"}""")]
    [InlineData("""{"rule": broken""")]
    public void Skips_information_an_admin_terminal_the_guardians_and_broken_lines(string line) =>
        Assert.False(FalcoParser.TryParse(line, out _));

    [Theory]
    [InlineData("Read sensitive file untrusted", "mitre_credential_access", "cat /etc/shadow", AttackType.SensitiveFileAccess)]
    [InlineData("Search Private Keys or Passwords", "mitre_credential_access", "find / -name id_rsa", AttackType.SensitiveFileAccess)]
    [InlineData("Run shell untrusted", "mitre_execution", "sh -c id", AttackType.SuspiciousExecution)]
    [InlineData("Execution from /dev/shm", "mitre_execution", "/dev/shm/x", AttackType.SuspiciousExecution)]
    [InlineData("Clear Log Activities", "mitre_defense_evasion", "sh -c : > /var/log/wtmp", AttackType.LogTampering)]
    [InlineData("XRC SSH authorized keys changed", "mitre_persistence", "tee -a /home/operatore/.ssh/authorized_keys", AttackType.Persistence)]
    [InlineData("PTRACE attached to process", "mitre_privilege_escalation", "gdb -p 1", AttackType.PrivilegeEscalation)]
    [InlineData("XRC Crypto miner started", "mitre_impact", "/tmp/.x/xmrig -o stratum+tcp://pool:3333", AttackType.CryptoMining)]
    public void Each_rule_lands_on_one_type(string rule, string tag, string command, AttackType expected) =>
        Assert.Equal(expected, AttackCatalog.FromHostAlert(
            new LogEvent(DateTimeOffset.UnixEpoch, LogEventKind.HostAlert, LogOrigin.Falco, "", Rule: rule, Detail: $"host,{tag}", Command: command)));
}

public class HostAlertLinkerTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 12, 3, 0, 0, TimeSpan.FromHours(1));
    private readonly ThreatAnalyzer _analyzer = new(new IntrusionPolicy(), new NoGeoLocator());

    private static LogEvent Fail(int minute, string ip, string user) =>
        new(T0.AddMinutes(minute), LogEventKind.FailedLogin, LogOrigin.Auth, ip, User: user, Port: 40000, Method: "password");

    private static LogEvent Login(int minute, string ip, string user) =>
        new(T0.AddMinutes(minute), LogEventKind.AcceptedLogin, LogOrigin.Auth, ip, User: user, Port: 40000, Method: "password");

    private static LogEvent Falco(int minute, string rule, string tag, string? user, string command, string? parent = null, int priority = 2) =>
        new(T0.AddMinutes(minute), LogEventKind.HostAlert, LogOrigin.Falco, "", User: user, Rule: rule, Detail: $"host,{tag}",
            Priority: priority, Command: command, Parent: parent);

    [Fact]
    public void What_an_intruder_did_joins_the_report_of_the_address_that_got_in()
    {
        var events = new List<LogEvent>();
        for (var i = 0; i < 4; i++) events.Add(Fail(i, "198.51.100.213", "operatore"));
        events.Add(Login(10, "198.51.100.213", "operatore"));
        events.Add(Falco(12, "Read sensitive file untrusted", "mitre_credential_access", "operatore", "cat /etc/shadow", "sudo < bash < sshd"));
        events.Add(Falco(13, "XRC SSH authorized keys changed", "mitre_persistence", "operatore", "tee -a .ssh/authorized_keys"));

        var linked = HostAlertLinker.Link(events);
        Assert.All(linked.Where(e => e.Kind == LogEventKind.HostAlert), e => Assert.Equal(("198.51.100.213", "ssh-session"), (e.SourceIp, e.LinkedBy)));

        var report = Assert.Single(_analyzer.Reports(linked, []));
        Assert.Equal(nameof(Severity.Critical), report.Severity);
        Assert.Contains(nameof(AttackType.SensitiveFileAccess), report.AttackTypes);
        Assert.Contains(nameof(AttackType.Persistence), report.AttackTypes);
        Assert.Equal(2, report.HostActivity.Count);
    }

    [Fact]
    public void An_ordinary_login_that_reads_shadow_is_for_a_person_to_check_not_critical()
    {
        var events = new List<LogEvent>
        {
            Login(0, "192.0.2.10", "admin"),
            Falco(5, "Read sensitive file untrusted", "mitre_credential_access", "admin", "cat /etc/shadow"),
        };
        var report = Assert.Single(_analyzer.Reports(HostAlertLinker.Link(events), []));
        Assert.Equal(nameof(Severity.High), report.Severity);
    }

    [Fact]
    public void A_shell_below_the_web_server_goes_to_the_address_that_sent_the_exploit()
    {
        var events = new List<LogEvent>
        {
            new(T0, LogEventKind.WebRequest, LogOrigin.WebAccess, "203.0.113.9", Method: "GET", Path: "/cgi-bin/ping?host=;id", Status: 200, Rule: "command-injection"),
            Falco(2, "Run shell untrusted", "mitre_execution", "www-data", "sh -c id", "php-fpm8.3 < nginx", priority: 3),
        };
        var alert = HostAlertLinker.Link(events).Single(e => e.Kind == LogEventKind.HostAlert);
        Assert.Equal(("203.0.113.9", "web-exploit"), (alert.SourceIp, alert.LinkedBy));
        Assert.Equal(Severity.Critical, ThreatAnalyzer.HostAlertSeverity(alert));
    }

    [Fact]
    public void An_alert_nobody_can_be_tied_to_stays_the_hosts()
    {
        var events = new List<LogEvent>
        {
            Login(0, "192.0.2.10", "admin"),
            // A login 13 hours earlier is no longer the session; root from cron has no login at all.
            Falco(13 * 60, "Read sensitive file untrusted", "mitre_credential_access", "admin", "cat /etc/shadow"),
            Falco(5, "Clear Log Activities", "mitre_defense_evasion", "root", "sh -c : > /var/log/wtmp"),
        };
        var linked = HostAlertLinker.Link(events);
        Assert.All(linked.Where(e => e.Kind == LogEventKind.HostAlert), e => Assert.False(e.HasAddress));
        Assert.Empty(_analyzer.Reports(linked, []));
    }
}
