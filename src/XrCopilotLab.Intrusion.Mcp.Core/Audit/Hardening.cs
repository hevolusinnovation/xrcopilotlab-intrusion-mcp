using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace XrCopilotLab.Intrusion.Mcp.Core.Audit;

/// <summary>
/// How the host is kept, read by the audit from files only root may open: the security updates that wait, the
/// firewall's own rules, the certificates the web server shows, the containers and what they may do to the host.
/// Unlike the rest of the audit it has no baseline: these are wrong or right whoever did them. Each part is null or
/// empty where the host has none of it (no dpkg, no UFW, no nginx, no Docker).
/// </summary>
public sealed record HardeningFacts(
    UpdateFacts? Updates,
    FirewallFacts? Firewall,
    IReadOnlyList<TlsCertificate> Certificates,
    IReadOnlyList<string> OldTlsProtocols,
    IReadOnlyList<AuditContainer> Containers,
    IReadOnlyList<string> DockerGroup);

/// <summary>
/// The distribution's updates. <c>Security</c>: installed packages for which the security lists apt downloaded have a
/// newer version; <c>Packages</c> names them (what faces the network first, not all of them on a neglected host).
/// <c>Checked</c>: when apt last downloaded its lists, as far as its files say. <c>Automatic</c>: unattended-upgrades
/// is installed and switched on. <c>RebootRequired</c>: an update is installed but the old kernel or library still runs.
/// </summary>
public sealed record UpdateFacts(int Security, IReadOnlyList<string> Packages, DateTimeOffset? Checked, bool Automatic, bool RebootRequired);

/// <summary>
/// UFW as its files say: on or off, what it does with a connection no rule names (<c>deny</c>, <c>reject</c>,
/// <c>allow</c>), and its incoming rules. <c>RulesRead</c> false: the rules could not be read, so nothing is said
/// about them. Rules written by hand with iptables or nft, and Docker's own, are not here.
/// </summary>
public sealed record FirewallFacts(bool Enabled, string Incoming, bool RulesRead, IReadOnlyList<FirewallRule> Rules);

/// <summary>One incoming rule of UFW: <c>Action</c> (<c>allow</c>, <c>limit</c>, <c>deny</c>, <c>reject</c>),
/// <c>Protocol</c> (<c>tcp</c>, <c>udp</c>, <c>any</c>), <c>Ports</c> as UFW writes them (<c>22</c>, <c>80,443</c>,
/// <c>8000:8100</c>, <c>any</c>) and <c>From</c> (<c>0.0.0.0/0</c> or <c>::/0</c>: anyone).</summary>
public sealed record FirewallRule(string Action, string Protocol, string Ports, string From);

/// <summary>A certificate nginx shows: the file, the names it is for, when it stops being valid.</summary>
public sealed record TlsCertificate(string File, string Names, DateTimeOffset Expires);

/// <summary>
/// A running container and what it may do to the host: <c>Privileged</c>, on the host's network or among its
/// processes, with Docker's socket or the host's whole disk inside it. <c>Ports</c>: the host's ports Docker publishes
/// for it on every address.
/// </summary>
public sealed record AuditContainer(string Name, string Image, bool Privileged, bool HostNetwork, bool HostPid, bool DockerSocket, bool HostDisk,
    IReadOnlyList<int> Ports);

/// <summary>
/// Reads the files behind <see cref="HardeningFacts"/>, given as text: dpkg's status and apt's lists, UFW's rules,
/// nginx's configuration, Docker's description of a container. Pure, so the same code is tested here and run as root.
/// </summary>
public static partial class HardeningParsers
{
    private static readonly string[] NetworkFacing =
    [
        "openssh", "openssl", "libssl", "nginx", "apache2", "libc6", "sudo", "linux-image", "docker", "containerd", "runc", "wireguard", "postgresql",
        "mysql", "mariadb", "redis", "php", "curl", "libcurl", "bind9", "postfix", "exim4", "dovecot", "samba", "systemd", "polkit", "glibc",
    ];
    private static readonly string[] OldProtocols = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"];

    /// <summary>True for a package that answers the network or gives root: a hole in it is reached first.</summary>
    public static bool FacesNetwork(string package) => NetworkFacing.Any(p => package.StartsWith(p, StringComparison.Ordinal));

    /// <summary>
    /// Apt's list of a security archive, by its file name. Ubuntu Pro's lists (esm) are left out: they name fixes a
    /// host without a subscription cannot install, and would wait for ever.
    /// </summary>
    public static bool IsSecurityList(string fileName) =>
        fileName.EndsWith("_Packages", StringComparison.Ordinal) && fileName.Contains("security", StringComparison.OrdinalIgnoreCase)
        && !fileName.StartsWith("esm.ubuntu.com", StringComparison.Ordinal);

    /// <summary>
    /// The installed packages (dpkg's <paramref name="status"/>) for which a security list has a newer version of the
    /// same architecture: the security updates that wait. Names, sorted.
    /// </summary>
    public static IReadOnlyList<string> PendingSecurity(string status, IEnumerable<string> securityLists)
    {
        var installed = new Dictionary<(string Name, string Arch), string>();
        foreach (var p in Stanzas(status).Where(p => p.Status.EndsWith(" installed", StringComparison.Ordinal))) installed[(p.Name, p.Arch)] = p.Version;
        var pending = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var list in securityLists)
            foreach (var p in Stanzas(list))
                if (installed.TryGetValue((p.Name, p.Arch), out var have) && CompareVersions(p.Version, have) > 0) pending.Add(p.Name);
        return pending.ToList();
    }

    // The stanzas of a dpkg status file or of an apt Packages list: only the fields that say which package, of which version.
    private static IEnumerable<(string Name, string Arch, string Version, string Status)> Stanzas(string text)
    {
        string? name = null, arch = null, version = null, status = null;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Length == 0)
            {
                if (name is not null && version is not null) yield return (name, arch ?? "", version, status ?? "");
                (name, arch, version, status) = (null, null, null, null);
            }
            else if (line.StartsWith("Package: ", StringComparison.Ordinal)) name = line[9..].Trim();
            else if (line.StartsWith("Architecture: ", StringComparison.Ordinal)) arch = line[14..].Trim();
            else if (line.StartsWith("Version: ", StringComparison.Ordinal)) version = line[9..].Trim();
            else if (line.StartsWith("Status: ", StringComparison.Ordinal)) status = line[8..].Trim();
        }
        if (name is not null && version is not null) yield return (name, arch ?? "", version, status ?? "");
    }

    /// <summary>
    /// Two Debian versions as dpkg compares them (<c>[epoch:]upstream[-revision]</c>): digits by value, letters before
    /// other signs, and <c>~</c> before everything, the end included (<c>1.0~rc1</c> comes before <c>1.0</c>).
    /// </summary>
    public static int CompareVersions(string a, string b)
    {
        var (ea, ua, ra) = Split(a);
        var (eb, ub, rb) = Split(b);
        if (ea != eb) return ea.CompareTo(eb);
        var upstream = ComparePart(ua, ub);
        return upstream != 0 ? upstream : ComparePart(ra, rb);

        static (int Epoch, string Upstream, string Revision) Split(string v)
        {
            var epoch = 0;
            var colon = v.IndexOf(':');
            if (colon > 0 && int.TryParse(v[..colon], NumberStyles.None, CultureInfo.InvariantCulture, out var e)) (epoch, v) = (e, v[(colon + 1)..]);
            var dash = v.LastIndexOf('-');
            return dash < 0 ? (epoch, v, "") : (epoch, v[..dash], v[(dash + 1)..]);
        }
    }

    private static int ComparePart(string a, string b)
    {
        static char At(string s, int i) => i < s.Length ? s[i] : '\0';
        static int Order(char c) => char.IsAsciiDigit(c) || c == '\0' ? 0 : c == '~' ? -1 : char.IsAsciiLetter(c) ? c : c + 256;
        int i = 0, j = 0;
        while (i < a.Length || j < b.Length)
        {
            while ((i < a.Length && !char.IsAsciiDigit(a[i])) || (j < b.Length && !char.IsAsciiDigit(b[j])))
            {
                var (x, y) = (Order(At(a, i)), Order(At(b, j)));
                if (x != y) return x.CompareTo(y);
                i++;
                j++;
            }
            while (At(a, i) == '0') i++;
            while (At(b, j) == '0') j++;
            var first = 0;
            while (char.IsAsciiDigit(At(a, i)) && char.IsAsciiDigit(At(b, j)))
            {
                if (first == 0) first = a[i].CompareTo(b[j]);
                i++;
                j++;
            }
            if (char.IsAsciiDigit(At(a, i))) return 1;
            if (char.IsAsciiDigit(At(b, j))) return -1;
            if (first != 0) return first;
        }
        return 0;
    }

    /// <summary>True when apt's settings (the files of <c>/etc/apt/apt.conf.d</c>, in their order) switch unattended-upgrades on.</summary>
    public static bool AutomaticUpdates(IEnumerable<string> aptConf)
    {
        var on = false;
        foreach (var line in aptConf.SelectMany(t => t.Split('\n')).Select(l => l.Trim()).Where(l => !l.StartsWith("//", StringComparison.Ordinal) && !l.StartsWith('#')))
            if (UnattendedUpgrade().Match(line) is { Success: true } m) on = m.Groups[1].Value is not ("0" or "");
        return on;
    }

    public static bool UfwEnabled(string ufwConf) =>
        ufwConf.Split('\n').Any(l => l.Trim().Equals("ENABLED=yes", StringComparison.OrdinalIgnoreCase));

    /// <summary>What UFW does with a connection no rule names (<c>/etc/default/ufw</c>): <c>deny</c>, <c>reject</c> or <c>allow</c>.</summary>
    public static string UfwIncoming(string defaults)
    {
        var value = defaults.Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.StartsWith("DEFAULT_INPUT_POLICY=", StringComparison.Ordinal))
            ?.Split('=', 2)[1].Trim('"', '\'', ' ').ToUpperInvariant();
        return value switch { "ACCEPT" => "allow", "REJECT" => "reject", _ => "deny" };
    }

    /// <summary>
    /// UFW's incoming rules, from the line it writes above each one in <c>user.rules</c>:
    /// <c>### tuple ### action protocol dport dst sport src [dapp sapp] direction</c>.
    /// </summary>
    public static IReadOnlyList<FirewallRule> UfwRules(string userRules)
    {
        const string marker = "### tuple ###";
        var rules = new List<FirewallRule>();
        foreach (var line in userRules.Split('\n').Select(l => l.Trim()).Where(l => l.StartsWith(marker, StringComparison.Ordinal)))
        {
            var f = line[marker.Length..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (f.Length < 7 || !f[^1].StartsWith("in", StringComparison.Ordinal)) continue;
            rules.Add(new FirewallRule(f[0].Split('_')[0], f[1], f[2], f[5]));
        }
        return rules;
    }

    /// <summary>True when the rule lets anyone in on this port.</summary>
    public static bool AllowsAnyone(FirewallRule rule, int port) =>
        rule.Action is "allow" or "limit" && rule.From is "0.0.0.0/0" or "::/0" && rule.Protocol is "tcp" or "any" && Covers(rule.Ports, port);

    private static bool Covers(string ports, int port)
    {
        if (ports == "any") return true;
        foreach (var part in ports.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var range = part.Split(':');
            if (!int.TryParse(range[0], NumberStyles.None, CultureInfo.InvariantCulture, out var from)) continue;
            var to = range.Length > 1 && int.TryParse(range[1], NumberStyles.None, CultureInfo.InvariantCulture, out var t) ? t : from;
            if (port >= from && port <= to) return true;
        }
        return false;
    }

    /// <summary>The single ports a rule names (<c>22</c>, <c>80,443</c>): not a range, not <c>any</c>.</summary>
    public static IEnumerable<int> SinglePorts(FirewallRule rule) =>
        rule.Ports.Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => int.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out var port) ? port : 0).Where(p => p > 0);

    /// <summary>What one nginx file says about TLS: the certificates it shows and the protocols too old to be safe it still accepts.</summary>
    public static (IReadOnlyList<string> Certificates, IReadOnlyList<string> OldProtocols) NginxTls(string conf)
    {
        var text = string.Join('\n', conf.Split('\n').Select(l => l.IndexOf('#') is var hash and >= 0 ? l[..hash] : l));
        var certificates = SslCertificate().Matches(text).Select(m => m.Groups[1].Value.Trim('"', '\'')).Where(p => p.StartsWith('/')).Distinct().ToList();
        var old = SslProtocols().Matches(text).SelectMany(m => m.Groups[1].Value.Split((char[])[' ', '\t', '\n'], StringSplitOptions.RemoveEmptyEntries))
            .Where(p => OldProtocols.Contains(p, StringComparer.OrdinalIgnoreCase)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        return (certificates, old);
    }

    /// <summary>
    /// A container from Docker's own files (<c>config.v2.json</c> and <c>hostconfig.json</c> under
    /// <c>/var/lib/docker/containers</c>), or null when it is not running or the files are not Docker's.
    /// </summary>
    public static AuditContainer? Container(string config, string hostConfig)
    {
        try
        {
            using var c = JsonDocument.Parse(config);
            using var h = JsonDocument.Parse(hostConfig);
            var (root, host) = (c.RootElement, h.RootElement);
            if (root.ValueKind != JsonValueKind.Object || host.ValueKind != JsonValueKind.Object) return null;
            if (!(root.TryGetProperty("State", out var state) && Flag(state, "Running"))) return null;
            var mounts = new List<string>();
            if (root.TryGetProperty("MountPoints", out var points) && points.ValueKind == JsonValueKind.Object)
                mounts.AddRange(points.EnumerateObject().Select(m => Text(m.Value, "Source")));
            if (host.TryGetProperty("Binds", out var binds) && binds.ValueKind == JsonValueKind.Array)
                mounts.AddRange(binds.EnumerateArray().Where(b => b.ValueKind == JsonValueKind.String).Select(b => b.GetString()!.Split(':')[0]));
            var ports = new SortedSet<int>();
            if (host.TryGetProperty("PortBindings", out var bindings) && bindings.ValueKind == JsonValueKind.Object)
                foreach (var binding in bindings.EnumerateObject().Where(b => b.Value.ValueKind == JsonValueKind.Array).SelectMany(b => b.Value.EnumerateArray()))
                {
                    var address = Text(binding, "HostIp");
                    if (address.StartsWith("127.", StringComparison.Ordinal) || address == "::1") continue;
                    if (int.TryParse(Text(binding, "HostPort"), NumberStyles.None, CultureInfo.InvariantCulture, out var port)) ports.Add(port);
                }
            return new AuditContainer(Text(root, "Name").TrimStart('/'),
                root.TryGetProperty("Config", out var cfg) ? Text(cfg, "Image") : "",
                Flag(host, "Privileged"), Text(host, "NetworkMode") == "host", Text(host, "PidMode") == "host",
                mounts.Any(m => m is "/var/run/docker.sock" or "/run/docker.sock"), mounts.Contains("/"), ports.ToList());
        }
        catch (JsonException) { return null; }

        static bool Flag(JsonElement e, string name) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;
        static string Text(JsonElement e, string name) =>
            e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : "";
    }

    [GeneratedRegex("""APT::Periodic::Unattended-Upgrade\s+"([^"]*)"\s*;""", RegexOptions.CultureInvariant)]
    private static partial Regex UnattendedUpgrade();

    [GeneratedRegex(@"(?<![\w_])ssl_certificate\s+([^;\s]+)\s*;", RegexOptions.CultureInvariant)]
    private static partial Regex SslCertificate();

    [GeneratedRegex(@"(?<![\w_])ssl_protocols\s+([^;]+);", RegexOptions.CultureInvariant)]
    private static partial Regex SslProtocols();
}
