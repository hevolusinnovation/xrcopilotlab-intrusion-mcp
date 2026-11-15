using XrCopilotLab.Intrusion.Mcp.Core.Analysis;
using XrCopilotLab.Intrusion.Mcp.Core.Geo;
using XrCopilotLab.Intrusion.Mcp.Core.Guard;
using XrCopilotLab.Intrusion.Mcp.Core.Models;
using XrCopilotLab.Intrusion.Mcp.Core.Queries;
using XrCopilotLab.Intrusion.Mcp.Core.Simulation;
using XrCopilotLab.Intrusion.Mcp.Core.Sources;
using Xunit;

namespace XrCopilotLab.Intrusion.Mcp.Core.Tests;

public class VpnTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 10, 0, 0, TimeSpan.Zero);

    // As xrc-vpn state writes it (one line; here indented).
    private static string StateJson(long now) => $$"""
        {"interface":"wgxrc","up":true,"updated":{{now - 20}},"port":51820,"endpoint":"vpn.example.com","subnet":"10.88.0.0/24","lan":["192.168.1.0/24"],
         "peers":[
          {"name":"mario-telefono","kind":"device","address":"10.88.0.2","lan":[],"created":{{now - 86400}},"endpoint":"198.51.100.21:40211","latestHandshake":{{now - 60}},"received":1200,"sent":800},
          {"name":"sede-milano","kind":"router","address":"10.88.0.3","lan":["192.168.20.0/24"],"created":{{now - 86400}},"endpoint":"[2001:db8::7]:51820","latestHandshake":{{now - 7200}},"received":5,"sent":6},
          {"name":"nuovo-pc","kind":"device","address":"10.88.0.4","lan":[],"created":{{now - 600}},"endpoint":null,"latestHandshake":0,"received":0,"sent":0}
         ]}
        """;

    [Fact]
    public void The_state_file_gives_users_places_and_last_connections()
    {
        var vpn = VpnState.Parse(StateJson(Now.ToUnixTimeSeconds()));
        Assert.NotNull(vpn);
        Assert.True(vpn.Up);
        Assert.Equal(("vpn.example.com", 51820, "10.88.0.0/24"), (vpn.Endpoint, vpn.Port, vpn.Subnet));
        Assert.Equal(["192.168.1.0/24"], vpn.Lan);

        var mario = vpn.Peers[0];
        Assert.Equal(("mario-telefono", "device", "198.51.100.21"), (mario.Name, mario.Kind, mario.RemoteIp));
        Assert.True(VpnState.Connected(mario, Now));

        var milano = vpn.Peers[1];
        Assert.Equal(("router", "2001:db8::7"), (milano.Kind, milano.RemoteIp));
        Assert.Equal(["192.168.20.0/24"], milano.Lan);
        Assert.False(VpnState.Connected(milano, Now));

        var nuovo = vpn.Peers[2];
        Assert.Null(nuovo.LastHandshake);
        Assert.Null(nuovo.RemoteIp);
    }

    [Fact]
    public void The_state_file_carries_the_ipv6_side_too()
    {
        // As xrc-vpn writes it with IPv6 on: an IPv6 network inside the tunnel, internal networks of both kinds, a
        // user that connected to the server's public IPv6 address.
        var vpn = VpnState.Parse("""
            {"interface":"wgxrc","up":true,"updated":1794600000,"port":51820,"endpoint":"[2001:db8::2]","subnet":"10.88.0.0/24",
             "subnet6":"fdec:377e:c6b8::/64","lan":["192.168.50.0/24","2001:db8:50::/64"],
             "peers":[{"name":"laptop","kind":"device","address":"10.88.0.2","address6":"fdec:377e:c6b8::2","lan":[],"created":1794599000,
                       "endpoint":"[2001:db8::3]:37160","latestHandshake":1794599990,"received":1,"sent":2}]}
            """);
        Assert.NotNull(vpn);
        Assert.Equal("fdec:377e:c6b8::/64", vpn.Subnet6);
        Assert.Equal(["192.168.50.0/24", "2001:db8:50::/64"], vpn.Lan);
        var laptop = Assert.Single(vpn.Peers);
        Assert.Equal(("fdec:377e:c6b8::2", "2001:db8::3"), (laptop.Address6, laptop.RemoteIp));
    }

    [Theory]
    [InlineData("")]
    [InlineData("{\"interface\":")]
    [InlineData("not json")]
    public void A_half_written_file_is_no_state(string text) => Assert.Null(VpnState.Parse(text));

    [Fact]
    public void The_simulated_vpn_flags_the_laptop_abroad_and_the_old_pc()
    {
        var queries = new GuardQueries(new SimulatedHostInspector(), Queries(), new FixedSite(), new ConnectionOptions(), new SyntheticGeo(), new IntrusionPolicy());
        var vpn = queries.Vpn(Now);
        Assert.True(vpn is { Installed: true, Up: true, Connected: 2 });
        var anna = vpn.Peers.Single(p => p.Name == "anna-portatile");
        Assert.False(anna.ExpectedCountry);
        Assert.Equal("RU", anna.Location?.CountryCode);
        Assert.True(vpn.Peers.Single(p => p.Name == "mario-telefono").ExpectedCountry);

        var findings = queries.Posture(Now, new Period(Now.AddDays(-7), Now)).Findings;
        var away = findings.Single(f => f.Id == "vpn-unexpected-country");
        Assert.Equal(nameof(Severity.High), away.Severity);
        Assert.Equal("sudo xrc-vpn revoke anna-portatile", away.Fix);
        Assert.Equal("sudo xrc-vpn revoke luca-vecchio-pc", findings.Single(f => f.Id == "vpn-unused-users").Fix);
    }

    [Fact]
    public void A_connection_from_abroad_before_the_period_is_not_reported_again()
    {
        var peer = Peer("anna-portatile", "RU", Now.AddDays(-10));
        var findings = PostureChecks.Evaluate(Facts(), Quiet(), vpn: Vpn(peer));
        Assert.DoesNotContain(findings, f => f.Id == "vpn-unexpected-country");
    }

    [Fact]
    public void A_vpn_with_no_public_address_says_so()
    {
        var findings = PostureChecks.Evaluate(Facts(), Quiet(), vpn: Vpn() with { Endpoint = null });
        Assert.Equal("vpn-endpoint-missing", Assert.Single(findings).Id);
    }

    [Fact]
    public void An_exposed_service_points_to_the_vpn()
    {
        var rdp = new ListeningPort(3389, "0.0.0.0", true);
        var without = PostureChecks.Evaluate(Facts(withVpn: false, rdp), Quiet()).Single(f => f.Id == "exposed-service-3389");
        Assert.Equal("sudo ./install.sh --with wireguard", without.Fix);

        var with = PostureChecks.Evaluate(Facts(withVpn: true, rdp), Quiet(), vpn: Vpn()).Single(f => f.Id == "exposed-service-3389");
        // UFW is on in Facts(): the fix allows the port from the VPN subnet and the on-site LAN, and denies the rest.
        Assert.Equal("sudo ufw allow from 10.88.0.0/24 to any port 3389 && sudo ufw allow from 192.168.1.0/24 to any port 3389 && sudo ufw deny 3389", with.Fix);
        Assert.Contains("The VPN is already here", with.Recommendation, StringComparison.Ordinal);
    }

    [Fact]
    public void A_stopped_vpn_names_its_unit()
    {
        var facts = Facts() with { Guardians = [.. Facts().Guardians.Where(g => g.Name != "wireguard"), G("wireguard", running: false)] };
        var stopped = PostureChecks.Evaluate(facts, Quiet(), vpn: Vpn()).Single(f => f.Id == "guardian-stopped-wireguard");
        Assert.Equal("sudo systemctl enable --now wg-quick@wgxrc", stopped.Fix);
    }

    private static GuardianFacts G(string name, bool? running = true, string? mode = null, DateTimeOffset? rules = null) =>
        new(name, true, "1.0", running, mode, false, $"/var/log/{name}.log", true, true, Now, rules);

    private static HostFacts Facts(bool withVpn = true, params ListeningPort[] extra)
    {
        List<GuardianFacts> guardians =
        [
            G("sshd"), G("nginx"), G("ufw", mode: "blocking"), G("fail2ban", mode: "blocking"), G("crowdsec", mode: "detection"),
            G("suricata", mode: "detection", rules: Now.AddHours(-8)), G("falco", mode: "detection"), G("modsecurity", mode: "detection"),
        ];
        if (withVpn) guardians.Add(G("wireguard"));
        return new HostFacts(Now, guardians, [new(22, "0.0.0.0", true), .. extra], new SshFacts(false, "prohibit-password", 22),
            Audit: AuditTests.Unchanged(Now));
    }

    private static VpnPeerStatus Peer(string name, string country, DateTimeOffset? last) =>
        new(name, "device", "10.88.0.2", [], Now.AddDays(-20), last is { } at && Now - at < TimeSpan.FromMinutes(3), last, "203.0.113.9",
            new GeoLocation(GeoLocation.Public, country), country == "IT", 0, 0);

    private static VpnResult Vpn(params VpnPeerStatus[] peers) =>
        new("web-01", false, Now, true, true, 51820, "vpn.example.com", "10.88.0.0/24", ["192.168.1.0/24"], Now, 0,
            peers.Length == 0 ? [Peer("mario-telefono", "IT", Now.AddMinutes(-1))] : peers, "", null);

    private static IntrusionQueries Queries() => new(new EmptySource(), new NoGeoLocator(), new IntrusionPolicy());

    private static SummaryResult Quiet() => Queries().Summary(Now, new Period(Now.AddDays(-7), Now), 100);

    private sealed class FixedSite : ISiteLocation
    {
        public SiteLocation Current => new();
    }

    private sealed class EmptySource : ILogSource
    {
        public string Hostname => "web-01";
        public bool Simulated => false;
        public int MaxDays => 30;
        public IReadOnlyList<string> Describe() => [];
        public IReadOnlyList<LogEvent> Read(DateTimeOffset since, DateTimeOffset now) => [];
    }
}
