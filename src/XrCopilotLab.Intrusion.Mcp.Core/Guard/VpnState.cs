using System.Text.Json;

namespace XrCopilotLab.Intrusion.Mcp.Core.Guard;

/// <summary>
/// The customer's WireGuard VPN as <c>xrc-vpn state</c> writes it (<c>/run/xrcopilotlab-vpn/state.json</c>, every
/// minute): the users the customer added, and where each one last connected from. It carries no key of any kind.
/// <c>Endpoint</c> is the public address users connect to, null until the customer sets it (<c>xrc-vpn endpoint</c>).
/// <c>Subnet6</c>: the VPN's IPv6 network inside the tunnel, null when it is off. <c>Lan</c> mixes IPv4 and IPv6.
/// </summary>
public sealed record VpnFacts(
    bool Up,
    int Port,
    string? Endpoint,
    string Subnet,
    IReadOnlyList<string> Lan,
    DateTimeOffset Updated,
    IReadOnlyList<VpnPeerFacts> Peers,
    string? Subnet6 = null);

/// <summary>
/// One VPN user: a person's device or, with <c>Kind</c> <c>router</c>, another site and the networks behind it
/// (<c>Lan</c>). <c>RemoteIp</c>: the public address it last connected from; <c>LastHandshake</c> null if it never did.
/// </summary>
public sealed record VpnPeerFacts(
    string Name,
    string Kind,
    string Address,
    IReadOnlyList<string> Lan,
    DateTimeOffset Created,
    string? RemoteIp,
    DateTimeOffset? LastHandshake,
    long Received,
    long Sent,
    string? Address6 = null);

public static class VpnState
{
    /// <summary>WireGuard renews the session every two minutes while traffic flows: a handshake this recent means connected.</summary>
    public static readonly TimeSpan ConnectedWithin = TimeSpan.FromMinutes(3);

    /// <summary>The state file, or null when it is not one (a half-written file, another program's).</summary>
    public static VpnFacts? Parse(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;
            var peers = new List<VpnPeerFacts>();
            if (r.TryGetProperty("peers", out var list) && list.ValueKind == JsonValueKind.Array)
            {
                foreach (var p in list.EnumerateArray())
                {
                    var name = Str(p, "name");
                    var address = Str(p, "address");
                    if (name is null || address is null) continue;
                    var hs = Long(p, "latestHandshake");
                    peers.Add(new VpnPeerFacts(name, Str(p, "kind") ?? "device", address, Strings(p, "lan"), Time(Long(p, "created")),
                        RemoteIp(Str(p, "endpoint")), hs > 0 ? Time(hs) : null, Long(p, "received"), Long(p, "sent"), Str(p, "address6")));
                }
            }
            return new VpnFacts(r.TryGetProperty("up", out var up) && up.ValueKind == JsonValueKind.True, (int)Long(r, "port"), Str(r, "endpoint"),
                Str(r, "subnet") ?? "", Strings(r, "lan"), Time(Long(r, "updated")), peers, Str(r, "subnet6"));
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or ArgumentOutOfRangeException) { return null; }
    }

    public static bool Connected(VpnPeerFacts peer, DateTimeOffset now) =>
        peer.LastHandshake is { } at && now - at <= ConnectedWithin;

    /// <summary><c>203.0.113.9:51820</c> or <c>[2001:db8::1]:51820</c> to the address alone.</summary>
    public static string? RemoteIp(string? endpoint)
    {
        if (string.IsNullOrEmpty(endpoint)) return null;
        if (endpoint.StartsWith('['))
        {
            var close = endpoint.IndexOf(']');
            return close > 1 ? endpoint[1..close] : null;
        }
        var colon = endpoint.LastIndexOf(':');
        return colon > 0 ? endpoint[..colon] : endpoint;
    }

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static long Long(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var n) ? n : 0;

    private static List<string> Strings(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array
            ? v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToList()
            : [];

    private static DateTimeOffset Time(long unix) => DateTimeOffset.FromUnixTimeSeconds(unix);
}
