using System.Text;
using XrCopilotLab.Intrusion.Mcp.Core.Guard;
using XrCopilotLab.Intrusion.Mcp.Core.Models;

namespace XrCopilotLab.Intrusion.Mcp.Core.Audit;

/// <summary>
/// The signs of a break-in the logs do not show, read from the audit: an account, an SSH key or something that starts
/// by itself that was not there at the baseline, a second root, an account with no password, a library loaded into
/// every program, a program running from /tmp or from memory. An intruder who got in quietly, or cleaned the logs,
/// still has to leave one of these to come back. What the customer changed on purpose they confirm with
/// <c>xrc-audit accept</c>, and the checks go quiet. Pure.
/// </summary>
public static class AuditChecks
{
    public const string Area = "integrity";

    /// <summary>The audit runs every 15 minutes: silent this long, its timer stopped and its picture is old.</summary>
    public static readonly TimeSpan StaleAfter = TimeSpan.FromHours(1);

    /// <summary>The findings that end only when someone fixes the host or accepts the change, so advice on them can be
    /// verified. A suspicious process is not one: it also ends when the program exits.</summary>
    public static readonly IReadOnlyList<string> VerifiableIds =
    [
        "audit-missing", "audit-stale", "audit-uid0-account", "audit-empty-password", "audit-new-account", "audit-new-sudo",
        "audit-new-ssh-key", "audit-ld-preload", "audit-persistence-new", "audit-persistence-changed",
    ];

    private const string Accept = " If you made this change, confirm it: sudo xrc-audit accept. If you did not, someone else did: treat the host as compromised.";
    private const int Shown = 5;

    /// <summary><paramref name="breakInSince"/>: the start of the period read, when someone got in during it. What
    /// changed after that moment is then the intruder's until proven otherwise.</summary>
    public static IReadOnlyList<PostureFinding> Evaluate(AuditState audit, DateTimeOffset now, DateTimeOffset? breakInSince = null)
    {
        var findings = new List<PostureFinding>();
        var (cur, old) = (audit.Current, audit.Baseline);
        var since = $"not there at the baseline of {old.Time:u}";
        bool AfterBreakIn(DateTimeOffset at) => breakInSince is { } from && at >= from;
        const string brokenIn = " Someone got into the host in the same period.";

        if (now - cur.Time > StaleAfter)
            findings.Add(new("audit-stale", nameof(Severity.Medium), Area, "The host's audit has stopped",
                $"Last run {cur.Time:u}: what follows is the host as it was then.",
                "Check its timer (systemctl status xrcopilotlab-audit.timer) and why the last run failed (journalctl -u xrcopilotlab-audit).",
                "sudo systemctl enable --now xrcopilotlab-audit.timer"));

        // ---- Wrong whatever the baseline says ----
        var roots = cur.Accounts.Where(a => a.Uid == 0 && a.Name != "root").ToList();
        if (roots.Count > 0)
            findings.Add(new("audit-uid0-account", nameof(Severity.Critical), Area, "A second account is root",
                $"{List(roots.Select(a => Safe(a.Name)))}: UID 0, the same as root, under another name.",
                "No distribution and no package creates one: it is the classic way to keep root after a break-in. Treat the host as compromised, "
                + "remove the account and look at what else changed.", null));
        var open = cur.Accounts.Where(a => a.Login && a.Password == AuditParsers.PasswordEmpty).ToList();
        if (open.Count > 0)
            findings.Add(new("audit-empty-password", nameof(Severity.Critical), Area, "An account has no password",
                $"{List(open.Select(a => Safe(a.Name)))}: a login shell and an empty password.",
                "Lock the account or give it a password now, then find out who emptied it.",
                open.Count == 1 ? $"sudo passwd -l {Safe(open[0].Name)}" : null));

        // ---- What changed since the baseline ----
        var before = old.Accounts.GroupBy(a => a.Name, StringComparer.Ordinal).ToDictionary(x => x.Key, x => x.First(), StringComparer.Ordinal);
        var added = cur.Accounts.Where(a => a.Login && a.Uid != 0 && !(before.TryGetValue(a.Name, out var b) && b.Login)).ToList();
        if (added.Count > 0)
            findings.Add(new("audit-new-account", nameof(Severity.High), Area, "An account that can log in was added",
                List(added.Select(a => $"{Safe(a.Name)} (uid {a.Uid}, {(before.ContainsKey(a.Name) ? "it had no login shell" : "new")}"
                                       + $"{(a.Sudo ? ", can become root" : "")})")) + $": {since}.",
                "Ask who created it." + Accept, null));
        var promoted = cur.Accounts.Where(a => a.Sudo && before.TryGetValue(a.Name, out var b) && !b.Sudo && !added.Contains(a)).ToList();
        if (promoted.Count > 0)
            findings.Add(new("audit-new-sudo", nameof(Severity.High), Area, "An account can now become root",
                $"{List(promoted.Select(a => Safe(a.Name)))}: sudo rights {since}.",
                "Ask who gave them (group sudo, or a file in /etc/sudoers.d)." + Accept, null));

        var knownKeys = old.Keys.Select(k => (k.User, k.Fingerprint)).ToHashSet();
        var keys = cur.Keys.Where(k => !knownKeys.Contains((k.User, k.Fingerprint))).ToList();
        if (keys.Count > 0)
        {
            var hot = keys.Any(k => AfterBreakIn(k.Modified));
            findings.Add(new("audit-new-ssh-key", (hot || keys.Any(k => k.User == "root") ? Severity.Critical : Severity.High).ToString(), Area,
                "An SSH key was added",
                List(keys.Select(k => $"{Safe(k.User)}: {Safe(k.Type)} {Safe(k.Fingerprint)} in {Safe(k.File)}, changed {k.Modified:u}")) + $": {since}."
                + (hot ? brokenIn : ""),
                "Whoever holds that key logs in without a password, and no log of failed attempts will ever show it. Ask the account's owner; "
                + "if nobody knows the key, remove its line from the file." + Accept, null));
        }

        var known = old.Persistence.GroupBy(p => p.Path, StringComparer.Ordinal).ToDictionary(x => x.Key, x => x.First().Hash, StringComparer.Ordinal);
        bool Same(AuditPersistence p) => known.TryGetValue(p.Path, out var hash) && hash == p.Hash;
        var preload = cur.Persistence.Where(p => p.Kind == "preload" && !Same(p)).ToList();
        if (preload.Count > 0)
            findings.Add(new("audit-ld-preload", nameof(Severity.Critical), Area, "A library is loaded into every program",
                $"/etc/ld.so.preload has content, changed {preload[0].Modified:u}: {since}.",
                "It is how a rootkit hides files, processes and connections from every tool on the host. Unless you put it there yourself "
                + "(very few products need it), treat the host as compromised and check it from a clean system." + Accept, null));
        var starts = cur.Persistence.Where(p => p.Kind != "preload" && !p.Packaged && !known.ContainsKey(p.Path)).ToList();
        if (starts.Count > 0)
            findings.Add(new("audit-persistence-new", (starts.Any(p => AfterBreakIn(p.Modified)) ? Severity.Critical : Severity.High).ToString(), Area,
                "Something new starts by itself",
                List(starts.Select(p => $"{Safe(p.Path)} ({Safe(p.Kind)}, changed {p.Modified:u})")) + $": {since}, and no package owns it."
                + (starts.Any(p => AfterBreakIn(p.Modified)) ? brokenIn : ""),
                "A scheduled job or a service is how an intruder comes back after a reboot. Read each file: what does it run, and who put it there?" + Accept,
                null));
        var edited = cur.Persistence.Where(p => p.Kind != "preload" && !Same(p) && (p.Packaged ? p.Altered : known.ContainsKey(p.Path))).ToList();
        if (edited.Count > 0)
            findings.Add(new("audit-persistence-changed", (edited.Any(p => AfterBreakIn(p.Modified)) ? Severity.Critical : Severity.High).ToString(), Area,
                "Something that starts by itself was changed",
                List(edited.Select(p => $"{Safe(p.Path)} ({Safe(p.Kind)}, changed {p.Modified:u}{(p.Packaged ? ", no longer as its package installed it" : "")})"))
                + $": different from the baseline of {old.Time:u}." + (edited.Any(p => AfterBreakIn(p.Modified)) ? brokenIn : ""),
                "A line added to a job that already existed is harder to notice than a new file. Compare each one with what you expect it to run." + Accept,
                null));

        // ---- Running now ----
        if (cur.Processes.Count > 0)
            findings.Add(new("audit-suspicious-process", (breakInSince is null ? Severity.High : Severity.Critical).ToString(), Area,
                "A program is running from where no program belongs",
                List(cur.Processes.Select(p => $"pid {p.Pid} ({Safe(p.User)}): {Safe(p.Exe)}, {Why(p.Reason)}")) + $", seen at {cur.Time:u}."
                + (breakInSince is null ? "" : brokenIn),
                "Miners, backdoors and attack tools are dropped in /tmp or /dev/shm, or kept only in memory, because every account can write there. "
                + "Look at it before stopping it (ls -l /proc/<pid>/exe, its network connections), then find how it got there.", null));

        return findings;
    }

    private static string Why(string reason) => reason switch
    {
        "tmp" => "started from a directory anyone can write",
        "memfd" => "it exists only in memory, with no file on disk",
        "deleted" => "its file was deleted after it started",
        _ => Safe(reason),
    };

    private static string List(IEnumerable<string> items)
    {
        var all = items.ToList();
        return (all.Count > Shown ? $"{all.Count}, the first: " : "") + string.Join("; ", all.Take(Shown));
    }

    /// <summary>
    /// A name, a path or a fingerprint as evidence: only the characters such things are made of, the others shown as
    /// <c>?</c>. On a compromised host the intruder chooses these texts, and the evidence reaches an AI agent: with no
    /// spaces and no punctuation left, nothing in it can read as a sentence.
    /// </summary>
    public static string Safe(string text)
    {
        var sb = new StringBuilder(Math.Min(text.Length, 120));
        foreach (var c in text)
        {
            if (sb.Length == 120) { sb.Append('…'); break; }
            sb.Append(char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' or '/' or '@' or '+' or ':' ? c : '?');
        }
        return sb.ToString();
    }
}
