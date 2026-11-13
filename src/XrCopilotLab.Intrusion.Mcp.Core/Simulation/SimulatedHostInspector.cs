using XrCopilotLab.Intrusion.Mcp.Core.Guard;

namespace XrCopilotLab.Intrusion.Mcp.Core.Simulation;

/// <summary>
/// The protection of the simulated host, as <see cref="SyntheticHost"/> describes it: every guardian installed by
/// <c>install.sh --with</c> and running, CrowdSec and ModSecurity in detection only, UFW on, and SSH still accepting
/// passwords from the internet, which is how the night's intruder got in. The customer's VPN is up with four users: two
/// connected from Italy (a phone and the Milan site's router), a laptop that connected from Saint Petersburg, and an old
/// PC silent for three months.
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
        [new(22, "0.0.0.0", true), new(80, "0.0.0.0", true), new(443, "0.0.0.0", true), new(8470, "127.0.0.1", false)],
        new SshFacts(PasswordAuthentication: true, PermitRootLogin: "prohibit-password", Port: 22),
        Vpn: Vpn(now));
    }

    // Addresses in the simulated geography (SyntheticGeo): 198.51.100.21 Bari, .22 Milan; 203.0.113.9 Saint Petersburg.
    public static VpnFacts Vpn(DateTimeOffset now) => new(true, 51820, "vpn.example.com", "10.88.0.0/24", ["192.168.1.0/24"], now.AddSeconds(-20),
    [
        new("mario-telefono", "device", "10.88.0.2", [], now.AddDays(-120), "198.51.100.21", now.AddMinutes(-1), 48_200_000, 3_100_000),
        new("sede-milano", "router", "10.88.0.3", ["192.168.20.0/24"], now.AddDays(-200), "198.51.100.22", now.AddSeconds(-40), 912_000_000, 655_000_000),
        new("anna-portatile", "device", "10.88.0.4", [], now.AddDays(-45), SimulatedTravellerIp, now.AddHours(-2), 2_400_000, 310_000),
        new("luca-vecchio-pc", "device", "10.88.0.5", [], now.AddDays(-400), "198.51.100.23", now.AddDays(-95), 0, 0),
    ]);

    public const string SimulatedTravellerIp = "203.0.113.9";
}
