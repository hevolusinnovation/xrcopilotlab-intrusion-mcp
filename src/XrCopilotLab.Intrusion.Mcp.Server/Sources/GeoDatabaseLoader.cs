using System.IO.Compression;
using XrCopilotLab.Intrusion.Mcp.Core.Geo;

namespace XrCopilotLab.Intrusion.Mcp.Server.Sources;

/// <summary>Settings of the geolocation (<c>Geo:*</c>).</summary>
public sealed class GeoOptions
{
    public const string SectionName = "Geo";

    /// <summary>
    /// Path of the DB-IP "IP to City Lite" CSV (<c>dbip-city-lite-YYYY-MM.csv</c> or <c>.csv.gz</c>), downloaded from
    /// https://db-ip.com/db/lite.php. Licence CC BY 4.0: commercial use is allowed with the attribution this server
    /// returns. Empty = no geolocation in the real mode.
    /// </summary>
    public string? DbIpCityLiteCsv { get; set; }
}

/// <summary>Loads the geolocation database once, at startup. A missing or unreadable file means no geolocation, not a failure.</summary>
public static class GeoDatabaseLoader
{
    public const string DbIpAttribution = "IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0.";

    public static IGeoLocator Load(GeoOptions options, ILogger logger)
    {
        var path = options.DbIpCityLiteCsv;
        if (string.IsNullOrWhiteSpace(path)) return new NoGeoLocator();
        if (!File.Exists(path))
        {
            logger.LogWarning("Geo database {Path} not found: running without geolocation", path);
            return new NoGeoLocator();
        }

        var rows = new List<(UInt128, UInt128, GeoLocation)>();
        Stream stream = File.OpenRead(path);
        if (path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)) stream = new GZipStream(stream, CompressionMode.Decompress);
        using var reader = new StreamReader(stream);
        // One GeoLocation per distinct place: the CSV repeats the same city for thousands of ranges.
        var places = new Dictionary<(string?, string?, double, double), GeoLocation>();
        while (reader.ReadLine() is { } line)
        {
            if (!IpRangeGeoTable.TryParseDbIpCityRow(line, out var row)) continue;
            var l = row.Location;
            var key = (l.CountryCode, l.City, l.Latitude!.Value, l.Longitude!.Value);
            if (!places.TryGetValue(key, out var shared)) places[key] = shared = l;
            rows.Add((row.Start, row.End, shared));
        }

        logger.LogInformation("Geo database {Path}: {Rows} ranges, {Places} places", path, rows.Count, places.Count);
        return new IpRangeGeoTable(rows, DbIpAttribution);
    }
}
