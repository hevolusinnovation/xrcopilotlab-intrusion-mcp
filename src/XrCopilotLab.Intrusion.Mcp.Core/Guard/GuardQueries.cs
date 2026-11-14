using XrCopilotLab.Intrusion.Mcp.Core.Analysis;
using XrCopilotLab.Intrusion.Mcp.Core.Geo;
using XrCopilotLab.Intrusion.Mcp.Core.Models;
using XrCopilotLab.Intrusion.Mcp.Core.Queries;

namespace XrCopilotLab.Intrusion.Mcp.Core.Guard;

/// <summary>
/// How the toolkit finds where the server is for the page's map. It geolocates the server's own public IP, the same
/// way for every customer: no name, no coordinates typed by hand. <c>LocationUrl</c> is a service that returns the
/// caller's public IP location directly (ipapi.co by default), so no local geo database is needed for the marker.
/// <c>LocationFile</c>, when set, is read instead of calling out: a server with no outbound access (or the Docker lab,
/// where the tunnel container writes it) can still place the server on the map.
/// </summary>
public sealed class SiteOptions
{
    public const string SectionName = "Site";

    public List<string> LocationUrls { get; set; } = ["https://ipwho.is/", "https://ipapi.co/json/"];
    public string? LocationFile { get; set; }
}

/// <summary>Where the server is on the page's map, from its public IP. All fields may be null until it is resolved.</summary>
public sealed record SiteLocation(double? Latitude = null, double? Longitude = null, string? City = null, string? Country = null);

/// <summary>Resolves and caches the server's own location (its public IP geolocated).</summary>
public interface ISiteLocation
{
    SiteLocation Current { get; }
}

/// <summary>
/// How XRCopilotLab reaches this server (<c>Connection:*</c>). <c>PublicUrl</c>: the address on the customer's own
/// domain (<c>https://guardiano.cliente.it/intrusion-mcp</c>), published by their nginx with TLS: when it is set, it is
/// the address. Without it, a test tunnel (Microsoft Dev Tunnels) may give a temporary one, which its agent writes to
/// <c>TunnelUrlFile</c>; it changes when the tunnel is recreated.
/// </summary>
public sealed class ConnectionOptions
{
    public const string SectionName = "Connection";

    public string? PublicUrl { get; set; }
    public string TunnelUrlFile { get; set; } = "/var/lib/xrcopilotlab-intrusion-mcp/tunnel/url";
}

/// <summary>
/// The address XRCopilotLab should use. <c>Mode</c>: <c>domain</c> (the customer's own, stable), <c>tunnel</c> (a temporary
/// test address: fine for a trial, not for production), <c>local</c> (none: reachable only from this host's network).
/// <c>Api</c> is the base for a connection's HTTP tools, <c>Mcp</c> the MCP endpoint. <c>TunnelUrl</c> is set when a
/// test tunnel is open, also beside a domain (then it should be closed).
/// </summary>
public sealed record ConnectionInfo(string Mode, string? Url, string? Api, string? Mcp, bool Temporary, string? TunnelUrl, string Note);

/// <summary>
/// One guardian as the page and the agents see it. <c>Status</c>: <c>ok</c>, <c>stopped</c> (installed, not running),
/// <c>log-unreadable</c>, <c>missing</c> (not installed). <c>Role</c>: what it is for, in one line.
/// </summary>
public sealed record GuardianStatus(string Name, string Role, string Status, bool Installed, string? Version, bool? Running, string? Mode,
    bool Managed, string? Log, DateTimeOffset? LogUpdated, DateTimeOffset? RulesUpdated, string? Note);

public sealed record GuardiansResult(string Host, bool Simulated, DateTimeOffset Now, SiteLocation Site, ConnectionInfo Connection, IReadOnlyList<GuardianStatus> Guardians,
    IReadOnlyList<ListeningPort> Listening, SshFacts? Ssh);

/// <summary>
/// One VPN user as the page and the agents see it: where it last connected from (<c>Location</c>, geolocated) and
/// whether that country is one the customer's people are expected in (<c>Policy:AllowedCountries</c>).
/// </summary>
public sealed record VpnPeerStatus(string Name, string Kind, string Address, IReadOnlyList<string> Lan, DateTimeOffset Created, bool Connected,
    DateTimeOffset? LastHandshake, string? RemoteIp, GeoLocation? Location, bool ExpectedCountry, long Received, long Sent, string? Address6 = null);

/// <summary>
/// The customer's VPN: <c>Installed</c> once <c>install.sh --with wireguard</c> set it up, <c>Up</c> while it listens on
/// UDP <c>Port</c>. The customer adds and revokes the users with <c>xrc-vpn</c>: this is only what they did.
/// </summary>
public sealed record VpnResult(string Host, bool Simulated, DateTimeOffset Now, bool Installed, bool Up, int? Port, string? Endpoint, string? Subnet,
    IReadOnlyList<string> Lan, DateTimeOffset? Updated, int Connected, IReadOnlyList<VpnPeerStatus> Peers, string Note, string? Attribution,
    string? Subnet6 = null);

public sealed record SeverityCount(string Severity, int Findings);

public sealed record PostureResult(string Host, bool Simulated, Period Period, IReadOnlyList<SeverityCount> BySeverity, IReadOnlyList<PostureFinding> Findings);

/// <summary>The answers behind <c>intrusion_guardians</c>, <c>intrusion_vpn</c> and <c>intrusion_posture</c>. Read-only: nothing is changed.</summary>
public sealed class GuardQueries(IHostInspector inspector, IntrusionQueries intrusions, ISiteLocation site, ConnectionOptions connection, IGeoLocator geo,
    IntrusionPolicy policy)
{
    /// <summary>The posture reads a week of attacks: a quiet day says little about a configuration.</summary>
    public const int DefaultPostureHours = 7 * 24;

    private static readonly Dictionary<string, string> Roles = new(StringComparer.Ordinal)
    {
        ["sshd"] = "Remote login (SSH): its log says who tried passwords and who got in.",
        ["nginx"] = "Web server: its access log shows scans and exploits in the address of the requests.",
        ["ufw"] = "Host firewall: drops connections to closed ports and logs them.",
        ["fail2ban"] = "Bans for a while an address that fails too many logins.",
        ["crowdsec"] = "Recognises attack patterns (slow brute force, scans) and shares a blocklist; detection only without a bouncer.",
        ["suricata"] = "Network IDS: checks all traffic against known attack signatures, and sees the host calling a malware controller.",
        ["falco"] = "Watches what happens inside the host: sensitive files read, shells from the web server, keys added, miners.",
        ["modsecurity"] = "Web application firewall (OWASP CRS): reads every request, bodies included; detection only unless switched on.",
        ["wireguard"] = "The customer's VPN: their people and sites reach the internal network with a key per device; it does not answer anyone else.",
    };

    public GuardiansResult Guardians(DateTimeOffset now)
    {
        var facts = inspector.Inspect(now);
        return new GuardiansResult(intrusions.Host, intrusions.Simulated, now, site.Current, Connection(connection, facts.TunnelUrl),
            facts.Guardians.Select(g => new GuardianStatus(g.Name, Roles.GetValueOrDefault(g.Name, ""), StatusOf(g), g.Installed, g.Version, g.Running,
                g.Mode, g.Managed, g.Log, g.LogUpdated, g.RulesUpdated, g.Note)).ToList(),
            facts.Listening, facts.Ssh);
    }

    public PostureResult Posture(DateTimeOffset now, Period period)
    {
        var facts = inspector.Inspect(now);
        var findings = PostureChecks.Evaluate(facts, intrusions.Summary(now, period, IntrusionQueries.MaxTop), Connection(connection, facts.TunnelUrl),
            Vpn(facts, now));
        var counts = Enum.GetValues<Severity>().Reverse()
            .Select(s => new SeverityCount(s.ToString(), findings.Count(f => f.Severity == s.ToString())))
            .ToList();
        return new PostureResult(intrusions.Host, intrusions.Simulated, period, counts, findings);
    }

    public VpnResult Vpn(DateTimeOffset now) => Vpn(inspector.Inspect(now), now);

    private VpnResult Vpn(HostFacts facts, DateTimeOffset now)
    {
        var installed = facts.Guardians.Any(g => g.Name == "wireguard" && g.Installed);
        if (facts.Vpn is not { } vpn)
            return new VpnResult(intrusions.Host, intrusions.Simulated, now, installed, false, null, null, null, [], null, 0, [],
                installed ? "The VPN is installed but has not written its state yet (xrc-vpn state, every minute)."
                          : "No VPN: install.sh --with wireguard sets one up, whose users the customer adds with xrc-vpn.", geo.Attribution);
        var peers = vpn.Peers.Select(p =>
        {
            var location = p.RemoteIp is null ? null : geo.Locate(p.RemoteIp);
            return new VpnPeerStatus(p.Name, p.Kind, p.Address, p.Lan, p.Created, VpnState.Connected(p, now), p.LastHandshake, p.RemoteIp, location,
                policy.IsAllowedCountry(location?.CountryCode), p.Received, p.Sent, p.Address6);
        }).OrderByDescending(p => p.Connected).ThenByDescending(p => p.LastHandshake).ThenBy(p => p.Name, StringComparer.Ordinal).ToList();
        var connected = peers.Count(p => p.Connected);
        var note = !vpn.Up ? "The VPN is installed but its interface is down: nobody can connect."
            : vpn.Endpoint is null ? "Up, but no public address is set: the customer sets it with xrc-vpn endpoint before adding users."
            : $"Up on UDP {vpn.Port}; users connect to {vpn.Endpoint}. {peers.Count} user(s), {connected} connected now.";
        return new VpnResult(intrusions.Host, intrusions.Simulated, now, true, vpn.Up, vpn.Port, vpn.Endpoint, vpn.Subnet, vpn.Lan, vpn.Updated, connected,
            peers, note, geo.Attribution, vpn.Subnet6);
    }

    /// <summary>The customer's domain wins; a tunnel is the address only when there is no domain.</summary>
    public static ConnectionInfo Connection(ConnectionOptions options, string? tunnelUrl)
    {
        var domain = string.IsNullOrWhiteSpace(options.PublicUrl) ? null : options.PublicUrl.Trim().TrimEnd('/');
        var tunnel = string.IsNullOrWhiteSpace(tunnelUrl) ? null : tunnelUrl.Trim().TrimEnd('/');
        if (domain is not null)
            return new ConnectionInfo("domain", domain, domain + "/api", domain + "/mcp", false, tunnel,
                tunnel is null ? "The customer's own domain: a stable address."
                               : "The customer's own domain. A test tunnel is still open beside it: close it, XRCopilotLab must use the domain.");
        if (tunnel is not null)
            return new ConnectionInfo("tunnel", tunnel, tunnel + "/api", tunnel + "/mcp", true, tunnel,
                "A temporary test address (Dev Tunnels): it changes if the tunnel is recreated. Set Connection:PublicUrl to the customer's domain for production.");
        return new ConnectionInfo("local", null, null, null, false, null,
            "No public address: XRCopilotLab cannot reach this server yet. Publish it on the customer's domain (Connection:PublicUrl) or open a test tunnel.");
    }

    public static string StatusOf(GuardianFacts g) =>
        !g.Installed ? "missing" : g.Running == false ? "stopped" : g.LogExists && !g.LogReadable ? "log-unreadable" : "ok";
}
