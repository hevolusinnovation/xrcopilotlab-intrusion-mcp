using System.Globalization;
using System.Net;

namespace XrCopilotLab.Intrusion.Mcp.Core.Geo;

/// <summary>
/// A geolocation database as sorted, non-overlapping address ranges: what DB-IP Lite and similar CSV files contain.
/// Reserved addresses are classified first and never looked up.
/// </summary>
public sealed class IpRangeGeoTable : IGeoLocator
{
    private readonly UInt128[] _starts;
    private readonly UInt128[] _ends;
    private readonly GeoLocation[] _locations;

    public IpRangeGeoTable(IEnumerable<(UInt128 Start, UInt128 End, GeoLocation Location)> ranges, string? attribution)
    {
        var sorted = ranges.OrderBy(r => r.Start).ToArray();
        _starts = sorted.Select(r => r.Start).ToArray();
        _ends = sorted.Select(r => r.End).ToArray();
        _locations = sorted.Select(r => r.Location).ToArray();
        Attribution = attribution;
    }

    public int Count => _starts.Length;

    public string? Attribution { get; }

    public GeoLocation Locate(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address)) return GeoLocation.Of(GeoLocation.Unknown);
        var scope = IpScope.Classify(address);
        if (scope != GeoLocation.Public) return GeoLocation.Of(scope);

        var n = IpScope.ToNumber(address);
        var i = Array.BinarySearch(_starts, n);
        if (i < 0) i = ~i - 1;
        return i >= 0 && n <= _ends[i] ? _locations[i] : GeoLocation.Of(GeoLocation.Public);
    }

    /// <summary>
    /// One row of the DB-IP "IP to City Lite" CSV: <c>ip_start,ip_end,continent,country,stateprov,city,latitude,longitude</c>.
    /// Returns false for a row that does not have that shape.
    /// </summary>
    public static bool TryParseDbIpCityRow(string line, out (UInt128 Start, UInt128 End, GeoLocation Location) row)
    {
        row = default;
        var f = SplitCsv(line);
        if (f.Count < 8) return false;
        if (!IPAddress.TryParse(f[0], out var start) || !IPAddress.TryParse(f[1], out var end)) return false;
        if (!double.TryParse(f[6], NumberStyles.Float, CultureInfo.InvariantCulture, out var lat)) return false;
        if (!double.TryParse(f[7], NumberStyles.Float, CultureInfo.InvariantCulture, out var lon)) return false;

        var code = f[3];
        row = (IpScope.ToNumber(start), IpScope.ToNumber(end),
            new GeoLocation(GeoLocation.Public, code, CountryName(code), NullIfEmpty(f[5]), lat, lon));
        return true;
    }

    public static string? CountryName(string? code)
    {
        if (string.IsNullOrWhiteSpace(code) || code.Length != 2) return null;
        try { return new RegionInfo(code).EnglishName; }
        catch (ArgumentException) { return null; }
    }

    private static string? NullIfEmpty(string s) => s.Length == 0 ? null : s;

    private static List<string> SplitCsv(string line)
    {
        var fields = new List<string>(8);
        var sb = new System.Text.StringBuilder();
        var quoted = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (quoted)
            {
                if (c == '"' && i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                else if (c == '"') quoted = false;
                else sb.Append(c);
            }
            else if (c == '"') quoted = true;
            else if (c == ',') { fields.Add(sb.ToString()); sb.Clear(); }
            else sb.Append(c);
        }
        fields.Add(sb.ToString());
        return fields;
    }
}

/// <summary>No database: every public address is "public, place unknown".</summary>
public sealed class NoGeoLocator : IGeoLocator
{
    public string? Attribution => null;

    public GeoLocation Locate(string ip) =>
        IPAddress.TryParse(ip, out var a) ? GeoLocation.Of(IpScope.Classify(a)) : GeoLocation.Of(GeoLocation.Unknown);
}
