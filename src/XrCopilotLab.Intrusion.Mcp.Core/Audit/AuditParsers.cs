using System.Globalization;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace XrCopilotLab.Intrusion.Mcp.Core.Audit;

/// <summary>
/// Reads the files the audit collects, given as text: <c>passwd</c>, <c>shadow</c>, <c>group</c>, <c>sudoers</c>,
/// <c>authorized_keys</c>, dpkg's status. Pure, so the same code is tested here and run as root on the host.
/// </summary>
public static partial class AuditParsers
{
    public const string PasswordSet = "set";
    public const string PasswordLocked = "locked";
    public const string PasswordEmpty = "empty";
    public const string PasswordUnknown = "unknown";

    private static readonly HashSet<string> NoLoginShells = new(StringComparer.Ordinal) { "nologin", "false", "sync", "shutdown", "halt" };
    private static readonly string[] SudoGroups = ["sudo", "admin", "wheel"];

    // Where a program started from says a lot: nothing legitimate runs from a directory anyone can write.
    private static readonly string[] WritableDirs = ["/tmp/", "/var/tmp/", "/dev/shm/"];
    private static readonly string[] SystemDirs = ["/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/snap/", "/var/lib/", "/nix/"];

    /// <summary>
    /// The accounts of <c>/etc/passwd</c>, with the state of each password (<paramref name="shadow"/> null: unknown) and
    /// whether it can become root: member of sudo, admin or wheel, or named, alone or by a group, in a sudoers rule.
    /// </summary>
    public static IReadOnlyList<AuditAccount> Accounts(string passwd, string? shadow, string group, IEnumerable<string> sudoers)
    {
        var passwords = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var f in Fields(shadow ?? "", 2))
            passwords[f[0]] = f[1].Length == 0 ? PasswordEmpty : f[1][0] is '!' or '*' ? PasswordLocked : PasswordSet;

        var (sudoUsers, sudoGroups) = SudoNames(sudoers);
        sudoGroups.UnionWith(SudoGroups);
        var sudoGids = new HashSet<int>();
        foreach (var f in Fields(group, 3))
        {
            if (!sudoGroups.Contains(f[0])) continue;
            if (int.TryParse(f[2], CultureInfo.InvariantCulture, out var gid)) sudoGids.Add(gid);
            if (f.Length > 3) sudoUsers.UnionWith(f[3].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        }

        var accounts = new List<AuditAccount>();
        foreach (var f in Fields(passwd, 7))
        {
            if (!int.TryParse(f[2], CultureInfo.InvariantCulture, out var uid)) continue;
            _ = int.TryParse(f[3], CultureInfo.InvariantCulture, out var gid);
            // An empty shell is /bin/sh. A password field left empty in passwd itself means no password at all.
            var shell = f[6].Length == 0 ? "/bin/sh" : f[6];
            var password = f[1].Length == 0 ? PasswordEmpty : shadow is null ? PasswordUnknown : passwords.GetValueOrDefault(f[0], PasswordLocked);
            accounts.Add(new AuditAccount(f[0], uid, shell, !NoLoginShells.Contains(shell[(shell.LastIndexOf('/') + 1)..]), password,
                sudoUsers.Contains(f[0]) || sudoGids.Contains(gid)));
        }
        return accounts;
    }

    /// <summary>The home of each account, to look for its <c>authorized_keys</c>.</summary>
    public static IReadOnlyList<(string User, string Home)> Homes(string passwd) =>
        Fields(passwd, 7).Where(f => f[5].StartsWith('/') && f[5].Length > 1).Select(f => (f[0], f[5])).ToList();

    /// <summary>Who a set of sudoers files gives rights to: users, and groups (written <c>%name</c>). Aliases are not followed.</summary>
    public static (HashSet<string> Users, HashSet<string> Groups) SudoNames(IEnumerable<string> sudoers)
    {
        var users = new HashSet<string>(StringComparer.Ordinal);
        var groups = new HashSet<string>(StringComparer.Ordinal);
        foreach (var raw in sudoers.SelectMany(text => text.Split('\n')))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] is '#' or '@') continue;
            var who = line.Split((char[])[' ', '\t', '='], 2)[0];
            if (who is "Defaults" or "User_Alias" or "Runas_Alias" or "Host_Alias" or "Cmnd_Alias" || who.StartsWith("Defaults", StringComparison.Ordinal)) continue;
            foreach (var name in who.Split(',', StringSplitOptions.RemoveEmptyEntries))
            {
                if (name.StartsWith('%')) { if (name.Length > 1 && name[1] != '#') groups.Add(name[1..]); }
                else if (name != "ALL") users.Add(name);
            }
        }
        return (users, groups);
    }

    /// <summary>The public keys of one <c>authorized_keys</c> file, each with the fingerprint <c>ssh-keygen -l</c> would print.</summary>
    public static IReadOnlyList<AuditKey> Keys(string user, string file, string text, DateTimeOffset modified)
    {
        var keys = new List<AuditKey>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#') continue;
            var m = KeyLine().Match(line);
            if (!m.Success) continue;
            byte[] blob;
            try { blob = Convert.FromBase64String(m.Groups["blob"].Value); }
            catch (FormatException) { continue; }
            var comment = m.Groups["comment"].Value.Trim();
            keys.Add(new AuditKey(user, "SHA256:" + Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('='), m.Groups["type"].Value,
                comment.Length == 0 ? null : comment, file, modified));
        }
        return keys;
    }

    /// <summary>
    /// Why a running program is out of place, from the path of its executable as <c>/proc/&lt;pid&gt;/exe</c> gives it, or
    /// null when it is not. A deleted executable inside the system's directories is a program updated while running.
    /// </summary>
    public static string? ProcessReason(string exe)
    {
        const string deleted = " (deleted)";
        var gone = exe.EndsWith(deleted, StringComparison.Ordinal);
        var path = gone ? exe[..^deleted.Length] : exe;
        // runc copies itself to memory for an instant at every container start (its fix for CVE-2019-5736).
        if (path.StartsWith("/memfd:", StringComparison.Ordinal)) return path.StartsWith("/memfd:runc_cloned", StringComparison.Ordinal) ? null : "memfd";
        if (WritableDirs.Any(d => path.StartsWith(d, StringComparison.Ordinal))) return "tmp";
        return gone && !SystemDirs.Any(d => path.StartsWith(d, StringComparison.Ordinal)) ? "deleted" : null;
    }

    /// <summary>The configuration files dpkg installed and the MD5 each had (<c>/var/lib/dpkg/status</c>, <c>Conffiles:</c>).</summary>
    public static Dictionary<string, string> Conffiles(string status)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        var inside = false;
        foreach (var line in status.Split('\n'))
        {
            if (line.Length == 0 || line[0] != ' ') { inside = line.StartsWith("Conffiles:", StringComparison.Ordinal); continue; }
            if (!inside) continue;
            var f = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (f.Length >= 2 && f[0].StartsWith('/')) result[Canonical(f[0])] = f[1];
        }
        return result;
    }

    /// <summary>One spelling for a path on a merged-/usr system, where dpkg says <c>/lib/…</c> and the disk <c>/usr/lib/…</c>.</summary>
    public static string Canonical(string path) =>
        path.StartsWith("/usr/lib/", StringComparison.Ordinal) || path.StartsWith("/usr/bin/", StringComparison.Ordinal)
        || path.StartsWith("/usr/sbin/", StringComparison.Ordinal) ? path[4..] : path;

    // The lines of a colon-separated file with at least this many fields.
    private static IEnumerable<string[]> Fields(string text, int atLeast) =>
        text.Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l.Length > 0 && l[0] != '#').Select(l => l.Split(':')).Where(f => f.Length >= atLeast && f[0].Length > 0);

    // Options may come before the key type (command="…",no-pty): the type is the first known one at a word boundary.
    [GeneratedRegex(@"(?:^|\s)(?<type>ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp(?:256|384|521)|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)[ \t]+(?<blob>[A-Za-z0-9+/]+=*)(?<comment>.*)$",
        RegexOptions.CultureInvariant)]
    private static partial Regex KeyLine();
}
