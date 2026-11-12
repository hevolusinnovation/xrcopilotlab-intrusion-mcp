using System.Globalization;
using System.Net;
using System.Text.Json;
using XrCopilotLab.Intrusion.Mcp.Core.Models;

namespace XrCopilotLab.Intrusion.Mcp.Core.Parsing;

/// <summary>
/// The alerts of Falco's JSON file output (<c>/var/log/falco/events.json</c>, <c>json_output: true</c>), one object per line:
/// <code>
/// {"hostname":"web-01","output":"…","output_fields":{"fd.name":"/etc/shadow","proc.cmdline":"cat /etc/shadow","proc.pname":"sudo","user.loginname":"operatore","user.name":"root",…},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","filesystem","host","mitre_credential_access"],"time":"2026-11-12T11:35:53.410250641Z"}
/// </code>
/// A process started in an SSH session carries the client's address in its environment (<c>SSH_CLIENT</c>, appended by
/// <c>install.sh --with falco</c>): that is the alert's address, tied by <c>ssh-session</c>. Otherwise the alert has no
/// address (<see cref="LogEvent.SourceIp"/> empty) and the analysis looks for one (<see cref="Analysis.HostAlertLinker"/>). Informational and debug rules are skipped,
/// and so is a terminal opened in a container, which is an administrator's <c>docker exec</c> far more often than an
/// attack, and what the other guardians do themselves (Suricata opening its capture socket, fail2ban reading logs).
/// </summary>
public static class FalcoParser
{
    /// <summary>Kept: Emergency, Alert, Critical (1), Error, Warning (2), Notice (3).</summary>
    public const int MaxPriority = 3;

    private static readonly HashSet<string> Ignored = new(StringComparer.Ordinal) { "Terminal shell in container" };

    private static readonly HashSet<string> Guardians = new(StringComparer.Ordinal)
        { "suricata", "Suricata-Main", "falco", "crowdsec", "fail2ban-server", "cscli", "suricata-update" };

    public static bool TryParse(string line, out LogEvent? parsed)
    {
        parsed = null;
        if (!line.Contains("\"rule\"", StringComparison.Ordinal)) return false;
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            var rule = Text(root, "rule");
            if (rule is null || Ignored.Contains(rule)) return false;
            var priority = Priority(Text(root, "priority"));
            if (priority > MaxPriority) return false;
            if (!DateTimeOffset.TryParse(Nanos(Text(root, "time")), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var time)) return false;

            var fields = root.TryGetProperty("output_fields", out var f) && f.ValueKind == JsonValueKind.Object ? f : default;
            if (Field(fields, "proc.name") is { } process && Guardians.Contains(process)) return false;
            var tags = root.TryGetProperty("tags", out var t) && t.ValueKind == JsonValueKind.Array
                ? string.Join(",", t.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()))
                : null;

            // sudo clears SSH_CLIENT but leaves SUDO_USER: then the account is tied to its login by the analysis.
            var client = SshClient(Field(fields, "proc.env[SSH_CLIENT]"));
            parsed = new LogEvent(time, LogEventKind.HostAlert, LogOrigin.Falco, client ?? "",
                // The account that logged in (the kernel keeps it through sudo, when it has audit), else the one sudo
                // was run by, else the one the process runs as.
                User: Field(fields, "user.loginname") ?? Field(fields, "proc.env[SUDO_USER]") ?? Field(fields, "user.name"),
                Path: Field(fields, "fd.name") ?? Field(fields, "fs.path.target"),
                Rule: rule,
                Detail: string.IsNullOrEmpty(tags) ? null : tags,
                Priority: priority,
                Command: Field(fields, "proc.cmdline"),
                Parent: Ancestry(fields),
                LinkedBy: client is null ? null : "ssh-session");
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>The parent and the grandparents Falco knows, nearest first: <c>sh &lt; php-fpm8.3 &lt; nginx</c>.</summary>
    private static string? Ancestry(JsonElement fields)
    {
        var names = new[] { "proc.pname", "proc.aname[2]", "proc.aname[3]", "proc.aname[4]" }
            .Select(n => Field(fields, n)).TakeWhile(n => n is not null).ToList();
        return names.Count == 0 ? null : string.Join(" < ", names);
    }

    // "198.51.100.213 39183 22": the client's address, port, and the server's port.
    private static string? SshClient(string? value) =>
        value?.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() is { } ip && IPAddress.TryParse(ip, out var address)
            ? address.ToString()
            : null;

    private static int Priority(string? name) => name?.ToLowerInvariant() switch
    {
        "emergency" or "alert" or "critical" => 1,
        "error" or "warning" => 2,
        "notice" => 3,
        _ => 4,
    };

    // Falco writes nanoseconds; DateTimeOffset reads at most seven digits.
    private static string? Nanos(string? ts)
    {
        if (ts is null) return null;
        var dot = ts.IndexOf('.', StringComparison.Ordinal);
        if (dot < 0) return ts;
        var end = dot + 1;
        while (end < ts.Length && char.IsAsciiDigit(ts[end])) end++;
        return end - dot - 1 <= 7 ? ts : ts[..(dot + 8)] + ts[end..];
    }

    private static string? Text(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    // Falco writes <NA> for a field it could not fill (a process whose parent it never saw).
    private static string? Field(JsonElement fields, string name) =>
        fields.ValueKind == JsonValueKind.Object && Text(fields, name) is { Length: > 0 } v && v != "<NA>" ? v : null;
}
