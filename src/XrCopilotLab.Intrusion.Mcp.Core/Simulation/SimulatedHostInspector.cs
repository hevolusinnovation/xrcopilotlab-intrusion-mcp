using XrCopilotLab.Intrusion.Mcp.Core.Audit;
using XrCopilotLab.Intrusion.Mcp.Core.Guard;

namespace XrCopilotLab.Intrusion.Mcp.Core.Simulation;

/// <summary>
/// The protection of the simulated host, as <see cref="SyntheticHost"/> describes it: every guardian installed by
/// <c>install.sh --with</c> and running, CrowdSec and ModSecurity in detection only, UFW on, and SSH still accepting
/// passwords from the internet, which is how the night's intruder got in. The customer's VPN is up with four users: two
/// connected from Italy (a phone and the Milan site's router), a laptop that connected from Saint Petersburg, and an old
/// PC silent for three months. The audit shows what the night's intruder left behind: an SSH key added to the account
/// it entered with, and its miner still running from /dev/shm; and a host kept as many are: security updates that wait,
/// a certificate whose renewal stopped, a container Docker publishes past the firewall.
/// </summary>
public sealed class SimulatedHostInspector : IHostInspector
{
    public HostFacts Inspect(DateTimeOffset now)
    {
        var day = now.AddMinutes(-3);
        GuardianFacts G(string name, string version, string? mode, bool managed, string log, DateTimeOffset? rules = null, string? note = null) =>
            new(name, true, version, true, mode, managed, log, true, true, day, rules, note);
        return new HostFacts(now,
        [
            G("sshd", "1:9.6p1-3ubuntu13.14", null, false, "/var/log/auth.log"),
            G("nginx", "1.24.0-2ubuntu7.19", null, false, "/var/log/nginx/access.log"),
            G("ufw", "0.36.2-6", "blocking", false, "/var/log/ufw.log"),
            G("fail2ban", "1.0.2-3ubuntu0.1", "blocking", true, "/var/log/fail2ban.log"),
            G("crowdsec", "1.7.3", "detection", true, "/var/log/crowdsec.log", note: "no bouncer: its decisions are not enforced"),
            G("suricata", "1:8.0.8-0ubuntu1", "detection", true, "/var/log/suricata/eve.json", rules: now.AddHours(-10)),
            G("falco", "0.45.2", "detection", true, "/var/log/falco/events.json"),
            G("modsecurity", "3.0.12-1.1build2", "detection", true, "/var/log/modsecurity/audit.json", note: "OWASP CRS 3.3.5"),
            G("wireguard", "1.0.20210914-1ubuntu4", null, true, "/run/xrcopilotlab-vpn/state.json", note: "4 user(s), 2 connected now; users connect to vpn.example.com"),
        ],
        [new(22, "0.0.0.0", true), new(80, "0.0.0.0", true), new(443, "0.0.0.0", true), new(3000, "0.0.0.0", true), new(8470, "127.0.0.1", false)],
        new SshFacts(PasswordAuthentication: true, PermitRootLogin: "prohibit-password", Port: 22),
        Vpn: Vpn(now),
        Audit: Audit(now));
    }

    // Addresses in the simulated geography (SyntheticGeo): 198.51.100.21 Bari, .22 Milan; 203.0.113.9 Saint Petersburg.
    public static VpnFacts Vpn(DateTimeOffset now) => new(true, 51820, "vpn.example.com", "10.88.0.0/24", ["192.168.1.0/24"], now.AddSeconds(-20),
    [
        new("mario-telefono", "device", "10.88.0.2", [], now.AddDays(-120), "198.51.100.21", now.AddMinutes(-1), 48_200_000, 3_100_000),
        new("sede-milano", "router", "10.88.0.3", ["192.168.20.0/24"], now.AddDays(-200), "198.51.100.22", now.AddSeconds(-40), 912_000_000, 655_000_000),
        new("anna-portatile", "device", "10.88.0.4", [], now.AddDays(-45), SimulatedTravellerIp, now.AddHours(-2), 2_400_000, 310_000),
        new("luca-vecchio-pc", "device", "10.88.0.5", [], now.AddDays(-400), "198.51.100.23", now.AddDays(-95), 0, 0),
    ]);

    // The baseline is a month old; since then only the intruder changed the host (SyntheticHost's Falco alerts tell the same story).
    public static AuditState Audit(DateTimeOffset now)
    {
        var then = now.AddDays(-30);
        var user = SyntheticHost.IncidentUser;
        AuditAccount[] accounts =
        [
            new("root", 0, "/bin/bash", true, AuditParsers.PasswordLocked, true),
            new("deploy", 1000, "/bin/bash", true, AuditParsers.PasswordLocked, true),
            new(user, 1001, "/bin/bash", true, AuditParsers.PasswordSet, true),
            new("m.ferri", 1002, "/bin/bash", true, AuditParsers.PasswordSet, false),
            new("backup", 34, "/usr/sbin/nologin", false, AuditParsers.PasswordLocked, false),
        ];
        AuditKey[] keys =
        [
            new("deploy", "SHA256:Zq0xHh2f1mUu3vQ4o0mJ7sN6c8yTtq1rB5wKpLd9eXA", "ssh-ed25519", "deploy@ci", "/home/deploy/.ssh/authorized_keys", now.AddDays(-210)),
            new("m.ferri", "SHA256:u7Jt3mC1xk9Pq2bVw8hRz5nL0sDfGy4aEo6iTcYeXrM", "ssh-ed25519", "m.ferri@portatile", "/home/m.ferri/.ssh/authorized_keys", now.AddDays(-150)),
        ];
        AuditPersistence[] jobs =
        [
            new("cron", "/etc/cron.d/backup-notturno", "5d41402abc4b2a76b9719d911017c592a3f5c1e0b7d2e8f94c6a1b3d5e7f9a0b", now.AddDays(-180), false, false),
            new("systemd", "/etc/systemd/system/xrcopilotlab-intrusion-mcp.service", "9b74c9897bac770ffc029102a200c5de1f3a5b7c9d0e2f4a6b8c0d2e4f6a8b0c", now.AddDays(-60), false, false),
        ];
        var hardening = new HardeningFacts(
            new UpdateFacts(7, ["openssh-server", "libssl3t64", "nginx-common", "curl", "libxml2", "python3.12", "vim-common"], now.AddHours(-6), true, true),
            new FirewallFacts(true, "deny", true,
            [
                new("limit", "tcp", "22", "0.0.0.0/0"), new("allow", "tcp", "80,443", "0.0.0.0/0"), new("allow", "udp", "51820", "0.0.0.0/0"),
            ]),
            [new("/etc/letsencrypt/live/www.example.com/fullchain.pem", "www.example.com", now.AddDays(9))],
            [],
            [new("grafana", "grafana/grafana:11.2.0", false, false, false, false, false, [3000])],
            []);
        var baseline = new AuditSnapshot(AuditState.Version, then, accounts, keys, jobs, [], [], hardening);
        return new AuditState(baseline with
        {
            Time = now.AddMinutes(-4),
            Keys = [.. keys, new(user, "SHA256:9fK2wQx7LmT4vB1nZc6yRj8sHd3pGa5uEo0iXtYeWqM", "ssh-rsa", "kali@kali", $"/home/{user}/.ssh/authorized_keys", now.AddHours(-9))],
            Processes = [new(48213, user, "/dev/shm/.k/xmrig", "tmp", "/dev/shm/.k/xmrig -o stratum+tcp://203.0.113.66:3333 --background", now.AddHours(-9).AddMinutes(14))],
        }, baseline);
    }

    public const string SimulatedTravellerIp = "203.0.113.9";
}
