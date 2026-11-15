using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using XrCopilotLab.Intrusion.Mcp.Core.Models;

namespace XrCopilotLab.Intrusion.Mcp.Core.Parsing;

/// <summary>
/// The JSON audit log of ModSecurity v3 with the OWASP Core Rule Set (<c>SecAuditLogFormat JSON</c>, <c>Serial</c>), one
/// transaction per line:
/// <code>
/// {"transaction":{"client_ip":"198.51.100.7","time_stamp":"Thu Nov 12 13:51:22 2026","request":{"method":"POST","uri":"/login"},"response":{"http_code":200},"messages":[{"message":"Remote Command Execution: Unix Command Injection","details":{"ruleId":"932100","severity":"2","tags":["attack-rce",…]}},{"message":"Inbound Anomaly Score Exceeded (Total Score: 18)","details":{"ruleId":"949110",…}}]}}
/// </code>
/// A request is kept only when the CRS added up enough evidence to block it (rule 949110, "Inbound Anomaly Score
/// Exceeded"): in <c>DetectionOnly</c> it was let through, but it was an attack. Single warnings (a bare IP in the Host
/// header) are not. The time is the host's local time, without an offset.
/// </summary>
public static partial class ModSecurityParser
{
    /// <summary>The CRS rule that adds up the inbound anomaly score and decides to block.</summary>
    public const int BlockingRule = 949110;

    /// <summary>CRS severities 0-3 (emergency to error, "critical" for attacks) name the attack; 4 and 5 are hints.</summary>
    public const int MaxSeverity = 3;

    /// <summary>The CRS attack families (tag <c>attack-…</c>), most telling first, with the name the reports use.</summary>
    private static readonly (string Tag, string Family)[] Families =
    [
        ("attack-rce", "command-injection"),
        ("attack-sqli", "sql-injection"),
        ("attack-rfi", "remote-file-inclusion"),
        ("attack-lfi", "path-traversal"),
        ("attack-xss", "xss"),
        ("attack-php", "php-injection"),
        ("attack-java", "java-injection"),
        ("attack-injection-generic", "injection"),
        ("attack-injection-php", "php-injection"),
        ("attack-fixation", "session-fixation"),
        ("attack-generic", "generic-attack"),
        ("attack-reputation-scanner", "scanner-agent"),
        ("attack-prompt-injection", "prompt-injection"),
        ("attack-multipart-header", "protocol-violation"),
        ("attack-protocol", "protocol-violation"),
    ];

    /// <summary>Families that only say the request looks like a tool or breaks HTTP: a scan, not an exploit.</summary>
    private static readonly HashSet<string> ScanFamilies = new(StringComparer.Ordinal) { "scanner-agent", "protocol-violation" };

    public static bool TryParse(string line, TimeZoneInfo zone, out LogEvent? parsed)
    {
        parsed = null;
        if (!line.Contains("\"transaction\"", StringComparison.Ordinal)) return false;
        try
        {
            using var doc = JsonDocument.Parse(line);
            if (!doc.RootElement.TryGetProperty("transaction", out var t) || t.ValueKind != JsonValueKind.Object) return false;
            if (!IPAddress.TryParse(Text(t, "client_ip"), out var ip)) return false;
            if (!TryTime(Text(t, "time_stamp"), zone, out var time)) return false;
            if (!t.TryGetProperty("messages", out var messages) || messages.ValueKind != JsonValueKind.Array) return false;

            int? score = null;
            var found = new List<(int Rank, string Family, int RuleId, string Message)>();
            foreach (var m in messages.EnumerateArray())
            {
                if (!m.TryGetProperty("details", out var d) || d.ValueKind != JsonValueKind.Object) continue;
                var ruleId = int.TryParse(Text(d, "ruleId"), CultureInfo.InvariantCulture, out var id) ? id : 0;
                var message = Text(m, "message") ?? "";
                if (ruleId == BlockingRule || message.StartsWith("Inbound Anomaly Score Exceeded", StringComparison.Ordinal))
                {
                    score = Score().Match(message) is { Success: true } s ? int.Parse(s.Groups[1].Value, CultureInfo.InvariantCulture) : 0;
                    continue;
                }
                var tags = d.TryGetProperty("tags", out var tg) && tg.ValueKind == JsonValueKind.Array
                    ? tg.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToList()
                    : [];
                // CRS severity 4 and 5 (warning, notice) only add to the score: a bare IP in the Host header is not a family.
                if (int.TryParse(Text(d, "severity"), CultureInfo.InvariantCulture, out var severity) && severity > MaxSeverity) continue;
                var rank = Array.FindIndex(Families, f => tags.Contains(f.Tag, StringComparer.Ordinal));
                if (rank >= 0) found.Add((rank, Families[rank].Family, ruleId, message));
            }
            if (score is null || found.Count == 0) return false;
            // install.sh --with modsecurity adds rules for text written for an AI in the body (a chatbot's message):
            // their message names the rule, "AI prompt injection: instruction-override".
            var injected = found.FirstOrDefault(f => f.Family == PromptInjectionFamily).Message is { } said
                && said.StartsWith(PromptInjectionMessage, StringComparison.Ordinal)
                ? said[PromptInjectionMessage.Length..].Trim()
                : null;

            var first = found.MinBy(f => f.Rank);
            var request = t.TryGetProperty("request", out var r) && r.ValueKind == JsonValueKind.Object ? r : default;
            var response = t.TryGetProperty("response", out var rs) && rs.ValueKind == JsonValueKind.Object ? rs : default;
            var uri = request.ValueKind == JsonValueKind.Object ? Text(request, "uri") : null;
            parsed = new LogEvent(time, LogEventKind.WafAlert, LogOrigin.ModSecurity, ip.ToString(),
                Method: UntrustedText.Clean(request.ValueKind == JsonValueKind.Object ? Text(request, "method") : null, 16),
                Path: UntrustedText.Clean(uri, UntrustedText.MaxPath),
                Status: response.ValueKind == JsonValueKind.Object && response.TryGetProperty("http_code", out var c) && c.TryGetInt32(out var code) ? code : null,
                Rule: first.Message,
                Detail: string.Join(",", found.OrderBy(f => f.Rank).Select(f => f.Family).Distinct()),
                SignatureId: first.RuleId,
                Score: score,
                Injection: (uri is null ? null : UntrustedText.Injection(UntrustedText.Decode(uri))) ?? injected);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>The attack family of a WAF alert: the first family in <see cref="LogEvent.Detail"/>.</summary>
    public static string FamilyOf(LogEvent alert) => (alert.Detail ?? "").Split(',')[0];

    /// <summary>The family of the rules for text written for an AI (install.sh --with modsecurity, ids 200100-200199).</summary>
    public const string PromptInjectionFamily = "prompt-injection";

    /// <summary>How those rules start their message; the rest is the <see cref="UntrustedText.Injection"/> rule.</summary>
    public const string PromptInjectionMessage = "AI prompt injection:";

    /// <summary>
    /// An exploit if any family is one; a scan if the request only looked like a tool or broke HTTP; a prompt injection
    /// if text for an AI was all there was.
    /// </summary>
    public static AttackType TypeOf(LogEvent alert)
    {
        var families = (alert.Detail ?? "").Split(',').Where(f => f.Length > 0).ToList();
        if (families.Any(f => !ScanFamilies.Contains(f) && f != PromptInjectionFamily)) return AttackType.WebExploitAttempt;
        if (families.Contains(PromptInjectionFamily)) return AttackType.AiPromptInjection;
        return AttackType.WebVulnerabilityScan;
    }

    // "Thu Nov 12 13:51:22 2026", or with the day padded by a space ("Thu Nov  5 …").
    private static bool TryTime(string? text, TimeZoneInfo zone, out DateTimeOffset time)
    {
        time = default;
        if (text is null) return false;
        var compact = string.Join(' ', text.Split(' ', StringSplitOptions.RemoveEmptyEntries));
        if (!DateTime.TryParseExact(compact, ["ddd MMM d HH:mm:ss yyyy", "ddd MMM dd HH:mm:ss yyyy"], CultureInfo.InvariantCulture,
                DateTimeStyles.None, out var local)) return false;
        time = LocalTime.ToOffset(local, zone);
        return true;
    }

    private static string? Text(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    [GeneratedRegex(@"Total Score:\s*(\d+)", RegexOptions.CultureInvariant)]
    private static partial Regex Score();
}
