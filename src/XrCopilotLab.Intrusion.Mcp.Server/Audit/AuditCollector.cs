using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using XrCopilotLab.Intrusion.Mcp.Core.Audit;

namespace XrCopilotLab.Intrusion.Mcp.Server.Audit;

/// <summary>
/// The audit: the same binary started as <c>… audit</c> by <c>xrcopilotlab-audit.service</c> (root, every 15 minutes,
/// no network, nothing writable but its own state directory). It reads what the server's own account may not —
/// <c>/etc/shadow</c> for the state of the passwords, the users' <c>authorized_keys</c>, the scheduled jobs and the
/// services, the executable of every process — and writes one file the server reads: the host now, and the baseline.
/// It also reads how the host is kept: dpkg's and apt's files for the security updates that wait, UFW's rules, the
/// certificates nginx shows, Docker's description of its containers. Files only: it starts no program and has no network.
/// It changes nothing on the host and keeps no secret: no hash, no key, only fingerprints.
/// <list type="bullet">
/// <item><c>audit</c>: take the picture; the first run also takes the baseline.</item>
/// <item><c>audit --accept</c>: take the picture and make it the baseline ("this is how the host should be").</item>
/// <item><c>audit --status</c>: print what differs from the baseline, without taking a new picture.</item>
/// </list>
/// </summary>
public static class AuditCollector
{
    public const string DefaultStateFile = "/var/lib/xrcopilotlab-audit/state.json";

    private const int MaxFileBytes = 1024 * 1024;
    private const int MaxPackagesNamed = 40;
    private static readonly string[] CronDirs = ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
        "/var/spool/cron/crontabs", "/var/spool/cron"];
    private static readonly string[] PackagedRoots = ["/etc/cron", "/etc/systemd/", "/etc/rc.local", "/lib/systemd/", "/usr/lib/systemd/"];

    public static int Run(string[] args, TextWriter output)
    {
        var file = Value(args, "--state") ?? DefaultStateFile;
        var root = Value(args, "--root") ?? "/";
        try
        {
            if (args.Contains("--status")) return Status(file, output);
            var previous = File.Exists(file) ? AuditState.Parse(File.ReadAllText(file)) : null;
            var current = Collect(root, DateTimeOffset.UtcNow);
            var accept = args.Contains("--accept");
            if (accept && previous is not null) Print(new AuditState(current, previous.Baseline), output, "Accepted as the host's normal state:");
            var state = new AuditState(current, accept || previous is null ? current : previous.Baseline);
            Write(file, state.Serialize());
            output.WriteLine(accept || previous is null
                ? $"Baseline taken: {current.Accounts.Count(a => a.Login)} account(s) that can log in, {current.Keys.Count} SSH key(s), {current.Persistence.Count} thing(s) that start by themselves."
                : $"Audit taken at {current.Time:u} (baseline of {state.Baseline.Time:u}).");
            foreach (var skipped in current.Skipped) output.WriteLine($"  not read: {skipped}");
            return 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            output.WriteLine($"audit: {ex.Message}");
            return 1;
        }
    }

    private static int Status(string file, TextWriter output)
    {
        var state = File.Exists(file) ? AuditState.Parse(File.ReadAllText(file)) : null;
        if (state is null)
        {
            output.WriteLine($"No audit yet ({file}). Take one: xrc-audit run");
            return 1;
        }
        output.WriteLine($"Audit of {state.Current.Time:u}, baseline of {state.Baseline.Time:u}.");
        Print(state, output, "Different from the baseline:");
        // No ports here: the firewall's unused rules are judged by the service, which knows what listens.
        var kept = state.Current.Hardening is { } hardening ? HardeningChecks.Evaluate(hardening, state.Current.Time) : [];
        if (kept.Count > 0) output.WriteLine("How the host is kept (it ends when fixed, not with accept):");
        foreach (var f in kept) output.WriteLine($"  [{f.Severity}] {f.Title}: {f.Evidence}");
        return 0;
    }

    private static void Print(AuditState state, TextWriter output, string title)
    {
        var findings = AuditChecks.Evaluate(state, state.Current.Time);
        if (findings.Count == 0) { output.WriteLine("Nothing differs from the baseline."); return; }
        output.WriteLine(title);
        foreach (var f in findings) output.WriteLine($"  [{f.Severity}] {f.Title}: {f.Evidence}");
    }

    /// <summary>The host under <paramref name="root"/> (<c>/</c>, or a copy of a host's files in a test), as it is at <paramref name="now"/>.</summary>
    public static AuditSnapshot Collect(string root, DateTimeOffset now)
    {
        var host = new HostFiles(root);
        var passwd = host.Text("/etc/passwd") ?? "";
        var sudoers = new[] { "/etc/sudoers" }.Concat(host.Files("/etc/sudoers.d")).Select(f => host.Text(f)).OfType<string>().ToList();
        var accounts = AuditParsers.Accounts(passwd, host.Text("/etc/shadow"), host.Text("/etc/group") ?? "", sudoers);

        var keys = new List<AuditKey>();
        foreach (var (user, home) in AuditParsers.Homes(passwd))
            foreach (var path in new[] { $"{home}/.ssh/authorized_keys", $"{home}/.ssh/authorized_keys2" })
                if (host.Exists(path) && host.Text(path) is { } text) keys.AddRange(AuditParsers.Keys(user, path, text, host.Modified(path)));

        var packaged = host.Packaged();
        var conffiles = AuditParsers.Conffiles(host.Text("/var/lib/dpkg/status", limit: false) ?? "");
        var persistence = new List<AuditPersistence>();
        void Add(string kind, string path)
        {
            if (host.LinkTarget(path) is { } target)
            {
                // A unit switched on is a link to the unit a package installed; a masked one is a link to /dev/null.
                persistence.Add(new AuditPersistence(kind, path, Sha256("-> " + target), host.Modified(path),
                    target == "/dev/null" || packaged.Contains(AuditParsers.Canonical(target)), false));
                return;
            }
            if (host.Bytes(path) is not { } content) return;
            persistence.Add(new AuditPersistence(kind, path, Convert.ToHexStringLower(SHA256.HashData(content)), host.Modified(path),
                packaged.Contains(AuditParsers.Canonical(path)),
                conffiles.TryGetValue(AuditParsers.Canonical(path), out var md5) && !md5.Equals(Convert.ToHexStringLower(MD5.HashData(content)), StringComparison.OrdinalIgnoreCase)));
        }
        Add("cron", "/etc/crontab");
        foreach (var path in CronDirs.SelectMany(d => host.Files(d)).Where(p => !p.EndsWith("/.placeholder", StringComparison.Ordinal))) Add("cron", path);
        foreach (var path in host.Files("/etc/systemd/system", depth: 3)) Add("systemd", path);
        Add("rc-local", "/etc/rc.local");
        // Comments apart, an empty ld.so.preload loads nothing.
        if (host.Text("/etc/ld.so.preload") is { } preload && preload.Split('\n').Any(l => l.Trim() is { Length: > 0 } t && t[0] != '#'))
            Add("preload", "/etc/ld.so.preload");

        var processes = Processes(host, accounts);
        var hardening = Hardening(host, passwd, accounts);
        return new AuditSnapshot(AuditState.Version, now, accounts, keys.Take(AuditState.MaxEntries).ToList(),
            persistence.OrderBy(p => p.Path, StringComparer.Ordinal).Take(AuditState.MaxEntries).ToList(), processes, host.Skipped, hardening);
    }

    private static HardeningFacts Hardening(HostFiles host, string passwd, IReadOnlyList<AuditAccount> accounts)
    {
        // ---- Updates: what dpkg has against what apt's security lists offer ----
        UpdateFacts? updates = null;
        if (host.Text("/var/lib/dpkg/status", limit: false) is { } status)
        {
            const string lists = "/var/lib/apt/lists";
            var security = new List<string>();
            foreach (var list in host.Files(lists))
            {
                var name = list[(lists.Length + 1)..];
                if (HardeningParsers.IsSecurityList(name)) { if (host.Text(list, limit: false) is { } text) security.Add(text); }
                else if (name.Contains("security", StringComparison.OrdinalIgnoreCase) && name.Contains("_Packages.", StringComparison.Ordinal))
                    host.Note($"{list} (compressed: the security updates in it are not counted)");
            }
            var pending = HardeningParsers.PendingSecurity(status, security);
            var stamps = new[] { "/var/lib/apt/periodic/update-success-stamp", "/var/lib/apt/periodic/update-stamp", "/var/cache/apt/pkgcache.bin", lists }
                .Select(host.ModifiedIfThere).OfType<DateTimeOffset>().ToList();
            updates = new UpdateFacts(pending.Count,
                pending.OrderByDescending(HardeningParsers.FacesNetwork).ThenBy(p => p, StringComparer.Ordinal).Take(MaxPackagesNamed).ToList(),
                stamps.Count > 0 ? stamps.Max() : null,
                host.Exists("/usr/bin/unattended-upgrade")
                && HardeningParsers.AutomaticUpdates(host.Files("/etc/apt/apt.conf.d").Select(f => host.Text(f)).OfType<string>()),
                host.Exists("/run/reboot-required"));
        }

        // ---- UFW, as its own files say (the kernel's rules need the network this audit does not have) ----
        FirewallFacts? firewall = null;
        if (host.Text("/etc/ufw/ufw.conf") is { } ufw)
        {
            var rules = new[] { "/etc/ufw/user.rules", "/etc/ufw/user6.rules" }.Select(f => host.Text(f)).OfType<string>().ToList();
            firewall = new FirewallFacts(HardeningParsers.UfwEnabled(ufw), HardeningParsers.UfwIncoming(host.Text("/etc/default/ufw") ?? ""), rules.Count > 0,
                rules.SelectMany(HardeningParsers.UfwRules).Distinct().Take(AuditState.MaxEntries).ToList());
        }

        // ---- TLS: the certificates nginx shows and the protocols it accepts ----
        var certificates = new List<TlsCertificate>();
        var old = new List<string>();
        var nginx = new[] { "/etc/nginx/nginx.conf", "/etc/letsencrypt/options-ssl-nginx.conf" }
            .Concat(host.Files("/etc/nginx/conf.d")).Concat(host.Files("/etc/nginx/sites-enabled")).Concat(host.Files("/etc/nginx/snippets"));
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var conf in nginx)
        {
            if (host.Text(conf) is not { } text) continue;
            var (files, protocols) = HardeningParsers.NginxTls(text);
            if (protocols.Count > 0) old.Add($"{string.Join(' ', protocols)} in {conf}");
            foreach (var file in files.Where(seen.Add))
            {
                if (host.Text(file) is not { } pem) continue;
                try
                {
                    // A chain file starts with the site's own certificate; the ones after it are the authority's.
                    using var certificate = X509Certificate2.CreateFromPem(pem);
                    var names = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().SelectMany(e => e.EnumerateDnsNames()).ToList();
                    certificates.Add(new TlsCertificate(file, names.Count > 0 ? string.Join(", ", names) : certificate.GetNameInfo(X509NameType.SimpleName, false),
                        new DateTimeOffset(certificate.NotAfter.ToUniversalTime(), TimeSpan.Zero)));
                }
                catch (CryptographicException) { host.Note($"{file} (not a certificate this audit can read)"); }
            }
        }

        // ---- Docker: what each running container may do to the host ----
        var containers = new List<AuditContainer>();
        foreach (var dir in host.Directories("/var/lib/docker/containers").Order(StringComparer.Ordinal))
            if (host.Text($"{dir}/config.v2.json") is { } config && host.Text($"{dir}/hostconfig.json") is { } hostConfig
                && HardeningParsers.Container(config, hostConfig) is { } container)
                containers.Add(container);
        var trusted = accounts.Where(a => a.Uid == 0 || a.Sudo || !a.Login).Select(a => a.Name).ToHashSet(StringComparer.Ordinal);
        var docker = AuditParsers.GroupMembers(passwd, host.Text("/etc/group") ?? "", "docker").Where(m => !trusted.Contains(m)).ToList();

        return new HardeningFacts(updates, firewall, certificates.Take(AuditState.MaxEntries).ToList(), old,
            containers.OrderBy(c => c.Name, StringComparer.Ordinal).Take(AuditState.MaxEntries).ToList(), docker);
    }

    private static List<AuditProcess> Processes(HostFiles host, IReadOnlyList<AuditAccount> accounts)
    {
        var result = new List<AuditProcess>();
        var names = accounts.GroupBy(a => a.Uid).ToDictionary(g => g.Key, g => g.First().Name);
        var boot = host.Text("/proc/stat", limit: false)?.Split('\n').FirstOrDefault(l => l.StartsWith("btime ", StringComparison.Ordinal)) is { } line
                   && long.TryParse(line[6..].Trim(), CultureInfo.InvariantCulture, out var seconds) ? seconds : 0;
        foreach (var dir in host.Directories("/proc"))
        {
            if (!int.TryParse(dir[(dir.LastIndexOf('/') + 1)..], CultureInfo.InvariantCulture, out var pid) || pid == Environment.ProcessId) continue;
            // Kernel threads have no executable; a process that ended meanwhile has nothing left to read.
            if (host.LinkTarget($"{dir}/exe", note: false) is not { } exe || AuditParsers.ProcessReason(exe) is not { } reason) continue;
            var uid = host.Text($"{dir}/status", limit: false)?.Split('\n').FirstOrDefault(l => l.StartsWith("Uid:", StringComparison.Ordinal))
                ?.Split((char[])['\t', ' '], StringSplitOptions.RemoveEmptyEntries).ElementAtOrDefault(1);
            var user = int.TryParse(uid, CultureInfo.InvariantCulture, out var id) && names.TryGetValue(id, out var name) ? name : uid ?? "?";
            var command = host.Text($"{dir}/cmdline", limit: false)?.Replace('\0', ' ').Trim();
            result.Add(new AuditProcess(pid, user, exe, reason, string.IsNullOrEmpty(command) ? null : command, Started(host.Text($"{dir}/stat", limit: false), boot)));
            if (result.Count == AuditState.MaxEntries) break;
        }
        return result;
    }

    // /proc/<pid>/stat: the 22nd field is the start, in ticks (100 a second) after boot. The name, field 2, may hold spaces.
    private static DateTimeOffset? Started(string? stat, long boot)
    {
        if (stat is null || boot == 0) return null;
        var fields = stat[(stat.LastIndexOf(')') + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return fields.Length > 19 && long.TryParse(fields[19], CultureInfo.InvariantCulture, out var ticks)
            ? DateTimeOffset.FromUnixTimeSeconds(boot + ticks / 100) : null;
    }

    // Written beside and moved into place: the server never reads half a file. Readable by the server's group only.
    private static void Write(string file, string json)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(file))!);
        var temp = file + ".tmp";
        File.WriteAllText(temp, json);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
        File.Move(temp, file, overwrite: true);
    }

    private static string Sha256(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    private static string? Value(string[] args, string name)
    {
        var i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    /// <summary>The host's files by their path on the host, wherever <c>root</c> is. What exists but cannot be read is noted, once.</summary>
    private sealed class HostFiles(string root)
    {
        private readonly string _root = root.TrimEnd('/');
        private readonly SortedSet<string> _skipped = new(StringComparer.Ordinal);

        public IReadOnlyList<string> Skipped => _skipped.ToList();

        private string On(string path) => _root + path;
        private string Off(string path) => _root.Length > 0 && path.StartsWith(_root, StringComparison.Ordinal) ? path[_root.Length..] : path;

        public bool Exists(string path) => File.Exists(On(path));

        /// <summary>Something the audit did not read for a reason of its own, said with the others.</summary>
        public void Note(string what) => _skipped.Add(what);

        /// <summary>When a file or a directory last changed, or null when it is not there.</summary>
        public DateTimeOffset? ModifiedIfThere(string path)
        {
            try
            {
                FileSystemInfo entry = Directory.Exists(On(path)) ? new DirectoryInfo(On(path)) : new FileInfo(On(path));
                return entry.Exists ? new DateTimeOffset(entry.LastWriteTimeUtc, TimeSpan.Zero) : null;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
        }

        public byte[]? Bytes(string path, bool limit = true)
        {
            try
            {
                if (!File.Exists(On(path))) return null;
                using var stream = new FileStream(On(path), FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (!limit)
                {
                    using var all = new MemoryStream();
                    stream.CopyTo(all);
                    return all.ToArray();
                }
                var buffer = new byte[MaxFileBytes];
                var read = stream.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
                return buffer[..read];
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (!path.StartsWith("/proc/", StringComparison.Ordinal)) _skipped.Add(path);
                return null;
            }
        }

        public string? Text(string path, bool limit = true) => Bytes(path, limit) is { } bytes ? Encoding.UTF8.GetString(bytes) : null;

        public DateTimeOffset Modified(string path)
        {
            try { return new DateTimeOffset(new FileInfo(On(path)).LastWriteTimeUtc, TimeSpan.Zero); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return DateTimeOffset.UnixEpoch; }
        }

        /// <summary>Where a link points, as a path on the host, or null when the path is not a link.</summary>
        public string? LinkTarget(string path, bool note = true)
        {
            try
            {
                var target = new FileInfo(On(path)).LinkTarget;
                if (target is null) return null;
                return Off(target.StartsWith('/') ? target : Path.GetFullPath(target, Path.GetDirectoryName(On(path))!));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (note) _skipped.Add(path);
                return null;
            }
        }

        /// <summary>The files and links under a directory, links to directories not followed.</summary>
        public IEnumerable<string> Files(string dir, int depth = 1)
        {
            var result = new List<string>();
            try
            {
                if (!Directory.Exists(On(dir))) return result;
                foreach (var entry in new DirectoryInfo(On(dir)).EnumerateFileSystemInfos().OrderBy(e => e.Name, StringComparer.Ordinal))
                {
                    var path = $"{dir}/{entry.Name}";
                    if (entry is DirectoryInfo && entry.LinkTarget is null) { if (depth > 1) result.AddRange(Files(path, depth - 1)); }
                    else result.Add(path);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { _skipped.Add(dir); }
            return result;
        }

        public IEnumerable<string> Directories(string dir)
        {
            try { return Directory.Exists(On(dir)) ? Directory.GetDirectories(On(dir)).Select(Off).ToList() : []; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { _skipped.Add(dir); return []; }
        }

        /// <summary>The cron and systemd files the distribution's packages installed (dpkg's lists). Empty where there is no dpkg.</summary>
        public HashSet<string> Packaged()
        {
            var owned = new HashSet<string>(StringComparer.Ordinal);
            const string info = "/var/lib/dpkg/info";
            if (!Directory.Exists(On(info))) { _skipped.Add($"{info} (no dpkg: every job and service counts as not packaged)"); return owned; }
            foreach (var list in Files(info).Where(f => f.EndsWith(".list", StringComparison.Ordinal)))
                foreach (var line in (Text(list, limit: false) ?? "").Split('\n'))
                    if (PackagedRoots.Any(r => line.StartsWith(r, StringComparison.Ordinal))) owned.Add(AuditParsers.Canonical(line.TrimEnd('\r')));
            return owned;
        }
    }
}
