using System.Net;
using System.Net.Sockets;

namespace XrCopilotLab.Intrusion.Mcp.Core.Geo;

/// <summary>Addresses that no geolocation database can place: private networks, loopback, the documentation ranges.</summary>
public static class IpScope
{
    private static readonly (UInt128 Start, UInt128 End, string Scope)[] Reserved =
    [
        Range("10.0.0.0", "10.255.255.255", GeoLocation.Private),
        Range("172.16.0.0", "172.31.255.255", GeoLocation.Private),
        Range("192.168.0.0", "192.168.255.255", GeoLocation.Private),
        Range("100.64.0.0", "100.127.255.255", GeoLocation.Private),
        Range("169.254.0.0", "169.254.255.255", GeoLocation.Private),
        Range("127.0.0.0", "127.255.255.255", GeoLocation.Loopback),
        Range("192.0.2.0", "192.0.2.255", GeoLocation.Documentation),
        Range("198.51.100.0", "198.51.100.255", GeoLocation.Documentation),
        Range("203.0.113.0", "203.0.113.255", GeoLocation.Documentation),
        Range("::1", "::1", GeoLocation.Loopback),
        Range("fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", GeoLocation.Private),
        Range("fe80::", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", GeoLocation.Private),
        Range("2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", GeoLocation.Documentation),
    ];

    /// <summary><see cref="GeoLocation.Public"/>, or the reserved scope the address belongs to.</summary>
    public static string Classify(IPAddress ip)
    {
        var n = ToNumber(ip);
        foreach (var (start, end, scope) in Reserved)
            if (n >= start && n <= end) return scope;
        return GeoLocation.Public;
    }

    public static bool IsDocumentation(string ip) =>
        IPAddress.TryParse(ip, out var a) && Classify(a) == GeoLocation.Documentation;

    /// <summary>An IPv4 address as its IPv4-mapped IPv6 form, so both families sort on one line.</summary>
    public static UInt128 ToNumber(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            Span<byte> v4 = stackalloc byte[4];
            ip.TryWriteBytes(v4, out _);
            return new UInt128(0, 0xFFFF_0000_0000UL | ((ulong)v4[0] << 24) | ((ulong)v4[1] << 16) | ((ulong)v4[2] << 8) | v4[3]);
        }
        Span<byte> b = stackalloc byte[16];
        ip.TryWriteBytes(b, out _);
        ulong hi = 0, lo = 0;
        for (var i = 0; i < 8; i++) hi = (hi << 8) | b[i];
        for (var i = 8; i < 16; i++) lo = (lo << 8) | b[i];
        return new UInt128(hi, lo);
    }

    private static (UInt128, UInt128, string) Range(string start, string end, string scope) =>
        (ToNumber(IPAddress.Parse(start)), ToNumber(IPAddress.Parse(end)), scope);
}
