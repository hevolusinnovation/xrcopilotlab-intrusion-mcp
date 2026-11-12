using System.Diagnostics;
using System.Globalization;
using System.Net;
using XrCopilotLab.Intrusion.Mcp.Core.Guard;

namespace XrCopilotLab.Intrusion.Mcp.Server.Sources;

/// <summary>
/// Reads the host's protection without privileges and without changing anything: package versions from dpkg, service
/// states from systemd (over D-Bus, as any user may), the configuration files that are world-readable, the listening
/// sockets from <c>/proc/net</c>, and whether the toolkit can open each log. Kept for 30 seconds: the page asks often.
/// </summary>
public sealed class SystemHostInspector(LogFileOptions logs, ConnectionOptions connection, ILogger<SystemHostInspector> logger) : IHostInspector
{
    private static readonly TimeSpan CacheFor = TimeSpan.FromSeconds(30);
    private readonly Lock _lock = new();
    private HostFacts? _cached;

    private const string ModSecurityNginx = "/etc/nginx/conf.d/xrcopilotlab-modsecurity.conf";
    private const string ModSecurityMain = "/etc/modsecurity/xrcopilotlab/main.conf";

    public HostFacts Inspect(DateTimeOffset now)
    {
        lock (_lock)
        {
            if (_cached is not null && now - _cached.Time < CacheFor && now >= _cached.Time) return _cached;
            _cached = Read(now);
            return _cached;
        }
    }

    private HostFacts Read(DateTimeOffset now)
    {
        var packages = Packages("openssh-server", "nginx", "ufw", "fail2ban", "crowdsec", "crowdsec-firewall-bouncer-nftables",
            "crowdsec-firewall-bouncer-iptables", "suricata", "falco", "libnginx-mod-http-modsecurity", "modsecurity-crs");
        string? V(string p) => packages.GetValueOrDefault(p);
        var active = ActiveUnits("ssh", "sshd", "nginx", "fail2ban", "crowdsec", "suricata", "falco-modern-bpf", "falco-kmod", "falco-bpf", "falco");
        bool? Running(bool installed, params string[] units) => installed ? units.Any(active.Contains) : null;

        var nginxOn = V("nginx") is not null;
        var bouncer = V("crowdsec-firewall-bouncer-nftables") ?? V("crowdsec-firewall-bouncer-iptables");
        var ufwEnabled = Lines("/etc/ufw/ufw.conf").Any(l => l.Trim().Equals("ENABLED=yes", StringComparison.OrdinalIgnoreCase));

        var guardians = new List<GuardianFacts>
        {
            Guardian("sshd", V("openssh-server"), Running(V("openssh-server") is not null, "ssh", "sshd"), null, false, logs.AuthFiles),
            Guardian("nginx", V("nginx"), Running(nginxOn, "nginx"), null, false, logs.WebAccessFiles),
            Ufw(V("ufw"), ufwEnabled, now),
            Guardian("fail2ban", V("fail2ban"), Running(V("fail2ban") is not null, "fail2ban"), "blocking",
                File.Exists("/etc/fail2ban/jail.d/xrcopilotlab.conf"), logs.Fail2banFiles),
            Guardian("crowdsec", V("crowdsec"), Running(V("crowdsec") is not null, "crowdsec"), bouncer is null ? "detection" : "blocking", false, logs.CrowdsecFiles,
                note: bouncer is null ? "no bouncer: its decisions are not enforced" : $"firewall bouncer {bouncer}"),
            Guardian("suricata", V("suricata"), Running(V("suricata") is not null, "suricata"), "detection", File.Exists("/etc/suricata/.xrcopilotlab-managed"),
                logs.SuricataFiles, rules: Modified("/var/lib/suricata/rules/suricata.rules")),
            Guardian("falco", V("falco"), Running(V("falco") is not null, "falco-modern-bpf", "falco-kmod", "falco-bpf", "falco"), "detection",
                File.Exists("/etc/falco/.xrcopilotlab-managed"), logs.FalcoFiles),
            ModSecurity(V("libnginx-mod-http-modsecurity"), V("modsecurity-crs"), active.Contains("nginx")),
        };
        return new HostFacts(now, guardians, Listening(), Ssh(), TunnelUrl());
    }

    private GuardianFacts Guardian(string name, string? version, bool? running, string? mode, bool managed, List<string> patterns,
        DateTimeOffset? rules = null, string? note = null)
    {
        var log = patterns.Select(p => p.TrimEnd('*')).FirstOrDefault();
        var (exists, readable, updated) = Probe(log);
        return new GuardianFacts(name, version is not null, version, running, version is null ? null : mode, managed, log, exists, readable, updated, rules,
            version is null ? null : note);
    }

    // UFW is not a daemon. Without it, a firewall that writes UFW-style lines (the lab's iptables rules) still counts.
    private GuardianFacts Ufw(string? version, bool enabled, DateTimeOffset now)
    {
        var g = Guardian("ufw", version, null, enabled ? "blocking" : "off", false, logs.FirewallFiles);
        if (version is null && g.LogUpdated is { } at && now - at < TimeSpan.FromDays(7))
            return g with { Installed = true, Mode = "blocking", Note = "UFW is not installed: another firewall writes UFW-style lines" };
        return g;
    }

    private GuardianFacts ModSecurity(string? module, string? crs, bool nginxRunning)
    {
        var log = logs.ModSecurityFiles.Select(p => p.TrimEnd('*')).FirstOrDefault();
        var (exists, readable, updated) = Probe(log);
        if (module is null) return new GuardianFacts("modsecurity", false, null, null, null, false, log, exists, readable, updated);
        var managed = File.Exists(ModSecurityNginx);
        var engine = Lines(ModSecurityMain).Select(l => l.Trim()).FirstOrDefault(l => l.StartsWith("SecRuleEngine", StringComparison.Ordinal))?.Split(' ', 2)[^1];
        var on = managed || NginxMentions("modsecurity on");
        var mode = !on ? null : engine switch { "On" => "blocking", "DetectionOnly" => "detection", "Off" => "off", _ => "detection" };
        return new GuardianFacts("modsecurity", true, module, on && nginxRunning, mode, managed, log, exists, readable, updated,
            Note: !on ? "module installed but not switched on in nginx" : crs is null ? null : $"OWASP CRS {crs}");
    }

    private static bool NginxMentions(string text)
    {
        try
        {
            return new[] { "/etc/nginx/nginx.conf" }
                .Concat(Directory.Exists("/etc/nginx/conf.d") ? Directory.GetFiles("/etc/nginx/conf.d") : [])
                .Concat(Directory.Exists("/etc/nginx/sites-enabled") ? Directory.GetFiles("/etc/nginx/sites-enabled") : [])
                .Any(f => Lines(f).Any(l => !l.TrimStart().StartsWith('#') && l.Contains(text, StringComparison.Ordinal)));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    // The test tunnel's agent writes its public address there while the tunnel is open, and removes it when it closes.
    private string? TunnelUrl()
    {
        var url = Lines(connection.TunnelUrlFile).Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0);
        return url is not null && Uri.TryCreate(url, UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps ? url : null;
    }

    private static (bool Exists, bool Readable, DateTimeOffset? Updated) Probe(string? path)
    {
        if (path is null || !File.Exists(path)) return (false, false, null);
        var updated = Modified(path);
        try
        {
            using var _ = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return (true, true, updated);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return (true, false, updated); }
    }

    private static DateTimeOffset? Modified(string path)
    {
        try { return File.Exists(path) ? new DateTimeOffset(File.GetLastWriteTimeUtc(path), TimeSpan.Zero) : null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    private static IEnumerable<string> Lines(string path)
    {
        try { return File.Exists(path) ? File.ReadAllLines(path) : []; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }

    /// <summary>sshd's settings as it reads them: the first value of each keyword wins, Include expanded in place, Match blocks ignored.</summary>
    private static SshFacts? Ssh()
    {
        if (!File.Exists("/etc/ssh/sshd_config")) return null;
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var unreadable = new List<string>();
        Read("/etc/ssh/sshd_config", 0);
        return new SshFacts(
            !values.TryGetValue("PasswordAuthentication", out var pa) || pa.Equals("yes", StringComparison.OrdinalIgnoreCase),
            values.GetValueOrDefault("PermitRootLogin", "prohibit-password").ToLowerInvariant(),
            values.TryGetValue("Port", out var port) && int.TryParse(port, CultureInfo.InvariantCulture, out var p) ? p : 22,
            unreadable.Count == 0 ? null : $"not readable by the toolkit, so not counted: {string.Join(", ", unreadable)}");

        void Read(string path, int depth)
        {
            string[] lines;
            try { lines = File.ReadAllLines(path); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { unreadable.Add(path); return; }
            foreach (var raw in lines)
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith('#')) continue;
                var parts = line.Split((char[])[' ', '\t', '='], 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (parts.Length < 2) continue;
                if (parts[0].Equals("Match", StringComparison.OrdinalIgnoreCase)) return;
                if (parts[0].Equals("Include", StringComparison.OrdinalIgnoreCase) && depth < 4)
                {
                    foreach (var pattern in parts[1].Split(' ', StringSplitOptions.RemoveEmptyEntries))
                    {
                        var full = Path.IsPathRooted(pattern) ? pattern : Path.Combine("/etc/ssh", pattern);
                        var dir = Path.GetDirectoryName(full)!;
                        if (!Directory.Exists(dir)) continue;
                        foreach (var file in Directory.GetFiles(dir, Path.GetFileName(full)).Order(StringComparer.Ordinal)) Read(file, depth + 1);
                    }
                    continue;
                }
                values.TryAdd(parts[0], parts[1].Split(' ')[0]);
            }
        }
    }

    /// <summary>TCP sockets in LISTEN, from /proc/net/tcp and tcp6 (the host's, since the service shares its network).</summary>
    private static List<ListeningPort> Listening()
    {
        var result = new List<ListeningPort>();
        foreach (var (file, v6) in new[] { ("/proc/net/tcp", false), ("/proc/net/tcp6", true) })
        {
            foreach (var line in Lines(file).Skip(1))
            {
                var f = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (f.Length < 4 || f[3] != "0A") continue;
                var local = f[1].Split(':');
                if (local.Length != 2 || !int.TryParse(local[1], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var port)) continue;
                var address = Address(local[0], v6);
                if (address is null) continue;
                result.Add(new ListeningPort(port, address.ToString(), !IPAddress.IsLoopback(address)));
            }
        }
        return result.DistinctBy(p => (p.Port, p.Address)).OrderBy(p => p.Port).ThenBy(p => p.Address, StringComparer.Ordinal).ToList();
    }

    // /proc/net writes each 32-bit word of the address in the host's byte order (little endian on x64 and arm64).
    private static IPAddress? Address(string hex, bool v6)
    {
        try
        {
            var bytes = Convert.FromHexString(hex);
            for (var i = 0; i + 4 <= bytes.Length; i += 4) Array.Reverse(bytes, i, 4);
            var ip = new IPAddress(bytes);
            return ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;
        }
        catch (FormatException) { return null; }
    }

    private Dictionary<string, string> Packages(params string[] names)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in Run("dpkg-query", ["-W", "-f", "${Package} ${db:Status-Abbrev} ${Version}\n", .. names]))
        {
            var f = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (f.Length >= 3 && f[1].StartsWith("ii", StringComparison.Ordinal)) result[f[0]] = f[2];
        }
        return result;
    }

    private HashSet<string> ActiveUnits(params string[] units)
    {
        var states = Run("systemctl", ["is-active", .. units]);
        var active = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < Math.Min(units.Length, states.Count); i++)
            if (states[i].Trim() == "active") active.Add(units[i]);
        return active;
    }

    private List<string> Run(string program, string[] args)
    {
        try
        {
            var start = new ProcessStartInfo(program) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            foreach (var a in args) start.ArgumentList.Add(a);
            using var process = Process.Start(start)!;
            var output = process.StandardOutput.ReadToEndAsync();
            _ = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(5000)) { process.Kill(); return []; }
            return output.Result.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            logger.LogDebug("{Program} not available: {Error}", program, ex.Message);
            return [];
        }
    }
}
