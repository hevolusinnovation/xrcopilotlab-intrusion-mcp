using System.Text.Json;
using XrCopilotLab.Intrusion.Mcp.Core.Parsing;

namespace XrCopilotLab.Intrusion.Mcp.Core.Audit;

/// <summary>
/// What the host is, not what its logs say: who can log in, which SSH keys open it, what starts by itself, what is
/// running from a place no program belongs. Taken by the audit (<c>xrc-audit</c>, root, read-only, every 15 minutes),
/// which the toolkit's own service could not take: it has no right to read <c>/etc/shadow</c>, the users' homes or
/// other users' processes. It carries no secret: no password hash, no key, only fingerprints of public keys.
/// <c>Skipped</c>: what the audit could not read, so its silence there is not a clean bill. <c>Hardening</c>: how the
/// host is kept (updates, firewall rules, certificates, containers); null in a picture taken before the audit read it.
/// </summary>
public sealed record AuditSnapshot(
    int Version,
    DateTimeOffset Time,
    IReadOnlyList<AuditAccount> Accounts,
    IReadOnlyList<AuditKey> Keys,
    IReadOnlyList<AuditPersistence> Persistence,
    IReadOnlyList<AuditProcess> Processes,
    IReadOnlyList<string> Skipped,
    HardeningFacts? Hardening = null);

/// <summary>
/// One account of <c>/etc/passwd</c>. <c>Login</c>: its shell is a real one. <c>Password</c>: <c>set</c>,
/// <c>locked</c>, <c>empty</c> (anyone logs in) or <c>unknown</c> (shadow not read); never the hash. <c>Sudo</c>: it can
/// become root (group sudo, admin or wheel, or a rule in sudoers).
/// </summary>
public sealed record AuditAccount(string Name, int Uid, string Shell, bool Login, string Password, bool Sudo);

/// <summary>One public key that opens an account over SSH (<c>authorized_keys</c>): its fingerprint as <c>ssh-keygen -l</c> prints it.</summary>
public sealed record AuditKey(string User, string Fingerprint, string Type, string? Comment, string File, DateTimeOffset Modified);

/// <summary>
/// Something that starts by itself: <c>Kind</c> is <c>cron</c>, <c>systemd</c>, <c>rc-local</c> or <c>preload</c>
/// (<c>/etc/ld.so.preload</c>, a library loaded into every program). <c>Hash</c>: SHA-256 of the content, or of the
/// target for a link. <c>Packaged</c>: the file, or the unit a link points to, belongs to a package of the
/// distribution. <c>Altered</c>: a packaged configuration file that no longer matches what the package installed.
/// </summary>
public sealed record AuditPersistence(string Kind, string Path, string Hash, DateTimeOffset Modified, bool Packaged, bool Altered);

/// <summary>
/// A running program that should not be where it is. <c>Reason</c>: <c>tmp</c> (started from /tmp, /var/tmp or
/// /dev/shm), <c>memfd</c> (it exists only in memory), <c>deleted</c> (its file was removed after the start, outside
/// the system's directories).
/// </summary>
public sealed record AuditProcess(int Pid, string User, string Exe, string Reason, string? Command, DateTimeOffset? Started);

/// <summary>
/// The audit's state file: the host now, and the host as it was when the customer last said "this is how it should be"
/// (<c>xrc-audit accept</c>; the first run takes it by itself). The checks speak about what changed between the two.
/// </summary>
public sealed record AuditState(AuditSnapshot Current, AuditSnapshot Baseline)
{
    public const int Version = 1;

    /// <summary>The most entries of one kind kept: a host with more has a problem of its own.</summary>
    public const int MaxEntries = 1000;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public string Serialize() => JsonSerializer.Serialize(this, Json);

    /// <summary>
    /// The state file, or null when it is not one. Every text in it is the host's, and on a compromised host the
    /// intruder's (an account name, a key's comment, a command line): it is cleaned here, where the service reads it.
    /// </summary>
    public static AuditState? Parse(string json)
    {
        try
        {
            var state = JsonSerializer.Deserialize<AuditState>(json, Json);
            if (state?.Current is null) return null;
            var current = Clean(state.Current);
            return new AuditState(current, state.Baseline is null ? current : Clean(state.Baseline));
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException or InvalidOperationException) { return null; }
    }

    private static AuditSnapshot Clean(AuditSnapshot s) => new(s.Version, s.Time,
        (s.Accounts ?? []).Where(a => a?.Name is not null).Take(MaxEntries)
            .Select(a => new AuditAccount(User(a.Name), a.Uid, Path(a.Shell), a.Login, Word(a.Password), a.Sudo)).ToList(),
        (s.Keys ?? []).Where(k => k?.User is not null && k.Fingerprint is not null).Take(MaxEntries)
            .Select(k => new AuditKey(User(k.User), Word(k.Fingerprint), Word(k.Type), UntrustedText.Clean(k.Comment, UntrustedText.MaxUser), Path(k.File), k.Modified)).ToList(),
        (s.Persistence ?? []).Where(p => p?.Path is not null).Take(MaxEntries)
            .Select(p => new AuditPersistence(Word(p.Kind), Path(p.Path), Word(p.Hash), p.Modified, p.Packaged, p.Altered)).ToList(),
        (s.Processes ?? []).Where(p => p?.Exe is not null).Take(MaxEntries)
            .Select(p => new AuditProcess(p.Pid, User(p.User), Path(p.Exe), Word(p.Reason), UntrustedText.Clean(p.Command, UntrustedText.MaxCommand), p.Started)).ToList(),
        (s.Skipped ?? []).Where(x => x is not null).Take(MaxEntries).Select(Path).ToList(),
        s.Hardening is null ? null : Clean(s.Hardening));

    private static HardeningFacts Clean(HardeningFacts h) => new(
        h.Updates is { } u ? new UpdateFacts(Math.Max(0, u.Security), Words(u.Packages), u.Checked, u.Automatic, u.RebootRequired) : null,
        h.Firewall is { } f
            ? new FirewallFacts(f.Enabled, Word(f.Incoming), f.RulesRead, (f.Rules ?? []).Where(r => r is not null).Take(MaxEntries)
                .Select(r => new FirewallRule(Word(r.Action), Word(r.Protocol), Word(r.Ports), Word(r.From))).ToList())
            : null,
        (h.Certificates ?? []).Where(c => c?.File is not null).Take(MaxEntries).Select(c => new TlsCertificate(Path(c.File), Path(c.Names), c.Expires)).ToList(),
        (h.OldTlsProtocols ?? []).Where(x => x is not null).Take(MaxEntries).Select(Path).ToList(),
        (h.Containers ?? []).Where(c => c?.Name is not null).Take(MaxEntries)
            .Select(c => new AuditContainer(Word(c.Name), Path(c.Image), c.Privileged, c.HostNetwork, c.HostPid, c.DockerSocket, c.HostDisk,
                (c.Ports ?? []).Where(p => p is > 0 and < 65536).Take(100).ToList())).ToList(),
        (h.DockerGroup ?? []).Where(x => x is not null).Take(MaxEntries).Select(User).ToList());

    private static List<string> Words(IReadOnlyList<string>? raw) => (raw ?? []).Where(x => x is not null).Take(MaxEntries).Select(Word).ToList();

    private static string User(string? raw) => UntrustedText.Clean(raw, UntrustedText.MaxUser) ?? "";
    private static string Path(string? raw) => UntrustedText.Clean(raw, UntrustedText.MaxPath) ?? "";
    private static string Word(string? raw) => UntrustedText.Clean(raw, 100) ?? "";
}
