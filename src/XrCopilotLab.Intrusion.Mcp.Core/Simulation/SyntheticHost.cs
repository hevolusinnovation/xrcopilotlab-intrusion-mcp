using System.Globalization;

namespace XrCopilotLab.Intrusion.Mcp.Core.Simulation;

/// <summary>Settings of the simulated host (<c>Simulation:*</c>).</summary>
public sealed class SimulationOptions
{
    public const string SectionName = "Simulation";

    /// <summary>The host name written in the simulated auth.log.</summary>
    public string Hostname { get; set; } = "bastion-01";

    /// <summary>Same seed, same days: two replicas, or a restart, tell the same story.</summary>
    public int Seed { get; set; } = 20261110;

    /// <summary>How many days back the simulated logs go.</summary>
    public int Days { get; set; } = 30;

    /// <summary>The host's time zone (IANA id): the logs are written in local time.</summary>
    public string TimeZone { get; set; } = "Europe/Rome";

    /// <summary>Every how many days the night-time intrusion (slow brute force, then a successful login) happens. 1 = every night.</summary>
    public int IncidentEveryDays { get; set; } = 1;
}

/// <summary>The lines one simulated day wrote to the two logs.</summary>
public sealed record SimulatedDay(DateOnly Day, IReadOnlyList<string> Fail2banLines, IReadOnlyList<string> AuthLines);

/// <summary>
/// A synthetic Linux host exposed on the internet with SSH and nginx, protected by fail2ban. It generates, for any day,
/// the lines that day would have left in <c>/var/log/auth.log</c> and <c>/var/log/fail2ban.log</c>, and runs the
/// fail2ban rules on them (maxretry, findtime, bantime, recidive), so bans and unbans follow from the attempts.
/// Deterministic: the same seed and day always give the same lines. Pure: no clock, no I/O.
/// <para>What a day contains:</para>
/// <list type="bullet">
/// <item>SSH brute force from 25-45 addresses (most get banned), web vulnerability scans, web login brute force;</item>
/// <item>every fourth day a request flood on the site;</item>
/// <item>a distributed campaign on one account, from 14-25 home connections, each under the ban threshold;</item>
/// <item>one address banned three times, then by the recidive jail for a week;</item>
/// <item>the intrusion: from 00:52, one attempt every three minutes on <c>operatore</c> (slow enough that fail2ban never bans), then a successful login around 02:50;</item>
/// <item>legitimate logins: the nightly backup from the office, the deploy key in working hours, an administrator who mistypes once.</item>
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

    private static readonly string[] ValidUsers = ["root", "deploy", "operatore", "m.ferri", "backup"];

    private static readonly string[] AttackUsers =
    [
        "root", "root", "root", "admin", "admin", "test", "ubuntu", "user", "oracle", "postgres", "git", "ftpuser",
        "guest", "pi", "support", "administrator", "operator", "vpn", "scada", "hmi", "engineer", "backup", "deploy",
    ];

    private static readonly string[] CampaignUsers = ["admin", "scada", "engineer", "vpn"];

    private static readonly Jail Sshd = new("sshd", MaxRetry: 5, FindTime: TimeSpan.FromMinutes(10), BanTime: TimeSpan.FromHours(1));
    private static readonly Jail HttpAuth = new("nginx-http-auth", 5, TimeSpan.FromMinutes(10), TimeSpan.FromHours(1));
    private static readonly Jail BotSearch = new("nginx-botsearch", 3, TimeSpan.FromMinutes(10), TimeSpan.FromHours(1));
    private static readonly Jail LimitReq = new("nginx-limit-req", 10, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(10));
    private static readonly Jail Recidive = new("recidive", 3, TimeSpan.FromDays(1), TimeSpan.FromDays(7));

    private const int Fail2banPid = 812;

    public SimulationOptions Options { get; } = options;

    public SimulatedDay Generate(DateOnly day)
    {
        var rng = new Random(unchecked(Options.Seed * 31 + day.DayNumber * 7919));
        var start = day.ToDateTime(TimeOnly.MinValue);
        var attempts = new List<Attempt>();

        SshNoise(rng, start, attempts);
        WebScans(rng, start, attempts);
        WebLogins(rng, start, attempts);
        if (day.DayNumber % 4 == 1) Flood(rng, start, attempts);
        Campaign(rng, day, start, attempts);
        RepeatOffender(rng, start, attempts);
        if (Options.IncidentEveryDays > 0 && day.DayNumber % Options.IncidentEveryDays == 0) Intrusion(rng, start, attempts);
        Legitimate(rng, day, start, attempts);

        var zone = TimeZoneInfo.FindSystemTimeZoneById(Options.TimeZone);
        var fail2ban = new List<(DateTime At, string Line)>();
        var auth = new List<(DateTime At, string Line)>();
        var bans = new List<(DateTime At, string Ip)>();

        foreach (var group in attempts.GroupBy(a => a.Service))
            RunJail(JailOf(group.Key), group.OrderBy(a => a.At).ToList(), rng, zone, fail2ban, auth, bans);
        RunRecidive(bans, fail2ban);

        return new SimulatedDay(day,
            fail2ban.OrderBy(l => l.At).Select(l => l.Line).ToList(),
            auth.OrderBy(l => l.At).Select(l => l.Line).ToList());
    }

    // ---- scenarios -------------------------------------------------------------------------------------------------

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
            Burst(rng, into, $"198.51.100.{rng.Next(100, 200)}", Service.WebScan, day.AddSeconds(rng.Next(0, 86_000)), rng.Next(2, 13), 1, 9);
    }

    private static void WebLogins(Random rng, DateTime day, List<Attempt> into)
    {
        var count = rng.Next(2, 7);
        for (var i = 0; i < count; i++)
            Burst(rng, into, $"203.0.113.{rng.Next(1, 240)}", Service.WebAuth, day.AddSeconds(rng.Next(0, 86_000)), rng.Next(4, 26), 3, 21);
    }

    private static void Flood(Random rng, DateTime day, List<Attempt> into)
    {
        var count = rng.Next(1, 3);
        for (var i = 0; i < count; i++)
            Burst(rng, into, $"198.51.100.{rng.Next(100, 200)}", Service.WebFlood, day.AddHours(rng.Next(9, 20)).AddMinutes(rng.Next(60)), rng.Next(40, 81), 0, 3);
    }

    /// <summary>One account, many home connections, one or three tries each spread over hours: never five in ten minutes.</summary>
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

    private static void Burst(Random rng, List<Attempt> into, string ip, Service service, DateTime at, int count, int minGap, int maxGap)
    {
        for (var k = 0; k < count; k++)
        {
            into.Add(new Attempt(at, ip, service, null, 0));
            at = at.AddSeconds(rng.Next(minGap, maxGap + 1));
        }
    }

    private static int Port(Random rng) => rng.Next(32768, 61000);

    // ---- fail2ban emulation -----------------------------------------------------------------------------------------

    private void RunJail(Jail jail, List<Attempt> attempts, Random rng, TimeZoneInfo zone,
        List<(DateTime, string)> fail2ban, List<(DateTime, string)> auth, List<(DateTime, string)> bans)
    {
        var windows = new Dictionary<string, Queue<DateTime>>();
        var bannedUntil = new Dictionary<string, DateTime>();

        foreach (var a in attempts)
        {
            // A banned address is dropped by the firewall: the service never sees the attempt.
            if (bannedUntil.TryGetValue(a.Ip, out var until) && a.At < until) continue;

            if (a.Service == Service.Ssh) WriteAuth(a, rng, zone, auth);
            if (a.Success) continue;

            var found = a.At.AddMilliseconds(rng.Next(5, 900));
            fail2ban.Add((found, F2b(found, "filter", "INFO", jail.Name, $"Found {a.Ip} - {a.At:yyyy-MM-dd HH:mm:ss}")));

            if (!windows.TryGetValue(a.Ip, out var window)) windows[a.Ip] = window = new Queue<DateTime>();
            window.Enqueue(a.At);
            while (window.Count > 0 && a.At - window.Peek() > jail.FindTime) window.Dequeue();
            if (window.Count < jail.MaxRetry) continue;

            window.Clear();
            var ban = found.AddMilliseconds(rng.Next(100, 900));
            var unban = ban + jail.BanTime;
            bannedUntil[a.Ip] = unban;
            fail2ban.Add((ban, F2b(ban, "actions", "NOTICE", jail.Name, $"Ban {a.Ip}")));
            fail2ban.Add((unban, F2b(unban, "actions", "NOTICE", jail.Name, $"Unban {a.Ip}")));
            bans.Add((ban, a.Ip));
        }
    }

    /// <summary>The recidive jail reads fail2ban's own Ban lines: three within a day, a week's ban.</summary>
    private static void RunRecidive(List<(DateTime At, string Ip)> bans, List<(DateTime, string)> fail2ban)
    {
        foreach (var byIp in bans.GroupBy(b => b.Ip))
        {
            var window = new Queue<DateTime>();
            foreach (var (at, ip) in byIp.OrderBy(b => b.At))
            {
                var found = at.AddMilliseconds(400);
                fail2ban.Add((found, F2b(found, "filter", "INFO", Recidive.Name, $"Found {ip} - {at:yyyy-MM-dd HH:mm:ss}")));
                window.Enqueue(at);
                while (window.Count > 0 && at - window.Peek() > Recidive.FindTime) window.Dequeue();
                if (window.Count < Recidive.MaxRetry) continue;

                window.Clear();
                var ban = found.AddSeconds(1);
                fail2ban.Add((ban, F2b(ban, "actions", "NOTICE", Recidive.Name, $"Ban {ip}")));
                fail2ban.Add((ban + Recidive.BanTime, F2b(ban + Recidive.BanTime, "actions", "NOTICE", Recidive.Name, $"Unban {ip}")));
            }
        }
    }

    private void WriteAuth(Attempt a, Random rng, TimeZoneInfo zone, List<(DateTime, string)> auth)
    {
        var pid = rng.Next(1000, 65000);
        var at = a.At;
        var user = a.User ?? "root";
        if (a.Success)
        {
            var key = a.Method == "publickey" ? ": ED25519 SHA256:" + Fingerprint(user) : "";
            auth.Add((at, Auth(at, zone, pid, $"Accepted {a.Method} for {user} from {a.Ip} port {a.Port} ssh2{key}")));
            var opened = at.AddMilliseconds(40);
            auth.Add((opened, Auth(opened, zone, pid, $"pam_unix(sshd:session): session opened for user {user}(uid=1001) by {user}(uid=0)")));
            return;
        }

        if (Array.IndexOf(ValidUsers, user) < 0)
        {
            auth.Add((at, Auth(at, zone, pid, $"Invalid user {user} from {a.Ip} port {a.Port}")));
            at = at.AddMilliseconds(rng.Next(300, 2500));
            auth.Add((at, Auth(at, zone, pid, $"Failed password for invalid user {user} from {a.Ip} port {a.Port} ssh2")));
            at = at.AddMilliseconds(rng.Next(100, 900));
            auth.Add((at, Auth(at, zone, pid, $"Connection closed by invalid user {user} {a.Ip} port {a.Port} [preauth]")));
        }
        else
        {
            at = at.AddMilliseconds(rng.Next(300, 2500));
            auth.Add((at, Auth(at, zone, pid, $"Failed password for {user} from {a.Ip} port {a.Port} ssh2")));
            at = at.AddMilliseconds(rng.Next(100, 900));
            auth.Add((at, Auth(at, zone, pid, $"Connection closed by authenticating user {user} {a.Ip} port {a.Port} [preauth]")));
        }
    }

    private string Auth(DateTime local, TimeZoneInfo zone, int pid, string message)
    {
        var offset = zone.GetUtcOffset(local);
        var stamp = new DateTimeOffset(local, offset).ToString("yyyy-MM-dd'T'HH:mm:ss.ffffffzzz", CultureInfo.InvariantCulture);
        return $"{stamp} {Options.Hostname} sshd[{pid}]: {message}";
    }

    private static string F2b(DateTime local, string module, string level, string jail, string message) =>
        string.Create(CultureInfo.InvariantCulture,
            $"{local:yyyy-MM-dd HH:mm:ss},{local.Millisecond:000} {("fail2ban." + module),-24} [{Fail2banPid}]: {level,-7} [{jail}] {message}");

    private static string Fingerprint(string user) =>
        Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("synthetic-key-" + user))).TrimEnd('=');

    private static Jail JailOf(Service s) => s switch
    {
        Service.Ssh => Sshd,
        Service.WebAuth => HttpAuth,
        Service.WebScan => BotSearch,
        _ => LimitReq,
    };

    private enum Service { Ssh, WebAuth, WebScan, WebFlood }

    private sealed record Attempt(DateTime At, string Ip, Service Service, string? User, int Port, bool Success = false, string? Method = null);

    private sealed record Jail(string Name, int MaxRetry, TimeSpan FindTime, TimeSpan BanTime);
}
