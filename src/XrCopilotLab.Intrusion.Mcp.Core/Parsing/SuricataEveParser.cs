using System.Net;
using System.Text.Json;
using XrCopilotLab.Intrusion.Mcp.Core.Geo;
using XrCopilotLab.Intrusion.Mcp.Core.Models;

namespace XrCopilotLab.Intrusion.Mcp.Core.Parsing;

/// <summary>
/// The alerts of Suricata's <c>/var/log/suricata/eve.json</c>, one JSON object per line:
/// <code>
/// {"timestamp":"2026-11-10T03:12:40.118204+0100","event_type":"alert","src_ip":"10.30.0.15","src_port":51544,"dest_ip":"203.0.113.66","dest_port":80,"proto":"TCP","app_proto":"http","alert":{"action":"allowed","gid":1,"signature_id":2100498,"rev":7,"signature":"ET MALWARE Linux Backdoor CnC Checkin","category":"A Network Trojan was detected","severity":1}}
/// </code>
/// Every other <c>event_type</c> (flow, http, dns, tls, stats…) is skipped, and so are the low-priority alerts
/// (Suricata severity 3 and 4: engine events, policy and information signatures), which say nothing about an attacker.
/// The event's address is the other side: the source of an alert coming in, the destination of a connection the host
/// itself opened (<see cref="LogEvent.Outbound"/>), which is how a compromised host calling its controller shows up.
/// </summary>
public static class SuricataEveParser
{
    /// <summary>Suricata's severity 1 (high) and 2 (medium) are kept; 3 and 4 are noise for this server.</summary>
    public const int MaxPriority = 2;

    /// <param name="local">The host's own addresses. Empty: an alert from a private address to a public one is outbound.</param>
    public static bool TryParse(string line, IReadOnlySet<string> local, out LogEvent? parsed)
    {
        parsed = null;
        // Most lines are not alerts: skip them before parsing any JSON.
        if (!line.Contains("\"alert\"", StringComparison.Ordinal)) return false;
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            if (Text(root, "event_type") != "alert" || !root.TryGetProperty("alert", out var alert)) return false;
            if (!DateTimeOffset.TryParse(Suricata(Text(root, "timestamp")), System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.None, out var time)) return false;
            if (!IPAddress.TryParse(Text(root, "src_ip"), out var src) || !IPAddress.TryParse(Text(root, "dest_ip"), out var dest)) return false;

            var priority = alert.TryGetProperty("severity", out var s) && s.TryGetInt32(out var p) ? p : 3;
            if (priority > MaxPriority) return false;

            var outbound = IsOutbound(src, dest, local);
            var remote = outbound ? dest : src;
            var localPort = Int(root, outbound ? "src_port" : "dest_port");
            var remotePort = Int(root, outbound ? "dest_port" : "src_port");
            var appProto = Text(root, "app_proto");

            parsed = new LogEvent(time, LogEventKind.IdsAlert, LogOrigin.Suricata, remote.ToString(),
                Port: remotePort,
                TargetPort: outbound ? remotePort : localPort,
                Protocol: string.IsNullOrEmpty(appProto) || appProto == "failed" ? Text(root, "proto")?.ToLowerInvariant() : appProto,
                Rule: Text(alert, "signature"),
                Detail: Text(alert, "category"),
                SignatureId: Int(alert, "signature_id"),
                Priority: priority,
                Outbound: outbound);
            return parsed.Rule is not null;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool IsOutbound(IPAddress src, IPAddress dest, IReadOnlySet<string> local)
    {
        if (local.Count > 0) return local.Contains(src.ToString()) && !local.Contains(dest.ToString());
        return IpScope.Classify(src) is GeoLocation.Private or GeoLocation.Loopback && IpScope.Classify(dest) is not (GeoLocation.Private or GeoLocation.Loopback);
    }

    // Suricata writes the offset without a colon (+0100), which DateTimeOffset does not read.
    private static string? Suricata(string? ts) =>
        ts is { Length: > 5 } && (ts[^5] == '+' || ts[^5] == '-') ? ts[..^2] + ":" + ts[^2..] : ts;

    private static string? Text(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static int? Int(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var i) ? i : null;
}
