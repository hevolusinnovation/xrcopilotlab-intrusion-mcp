using System.Text.Json;
using XrCopilotLab.Intrusion.Mcp.Core.Guard;

namespace XrCopilotLab.Intrusion.Mcp.Server.Sources;

/// <summary>
/// Where the server is on the page's map, found the same way for every customer: it geolocates the server's own public
/// IP. By default it asks a service that returns the caller's location directly (<see cref="SiteOptions.LocationUrl"/>,
/// ipapi.co), so no local geo database is needed for the marker. A server with no outbound access, or the Docker lab
/// (where the tunnel container writes the file), uses <see cref="SiteOptions.LocationFile"/> instead. The result is
/// cached and refreshed in the background; it never blocks a request.
/// </summary>
public sealed class HttpSiteLocation : ISiteLocation, IDisposable
{
    private static readonly TimeSpan Refresh = TimeSpan.FromMinutes(30);
    private readonly SiteOptions _options;
    private readonly ILogger<HttpSiteLocation> _logger;
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(8) };
    private readonly Timer _timer;
    private volatile SiteLocation _current = new();

    public HttpSiteLocation(SiteOptions options, ILogger<HttpSiteLocation> logger)
    {
        _options = options;
        _logger = logger;
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("xrcopilotlab-intrusion-mcp");
        // Resolve soon after start, then on a slow timer. A failure leaves the last known value (or empty).
        _timer = new Timer(_ => Resolve(), null, TimeSpan.FromSeconds(3), Refresh);
    }

    public SiteLocation Current => _current;

    private void Resolve()
    {
        try
        {
            var found = FromFile() ?? FromService();
            if (found is not null && (found.Latitude is not null || found.City is not null)) _current = found;
        }
        catch (Exception ex)
        {
            _logger.LogDebug("Cannot resolve the server location: {Error}", ex.Message);
        }
    }

    // The lab (and any isolated server) writes the location here; our own format.
    private SiteLocation? FromFile()
    {
        var path = _options.LocationFile;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return null;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            var r = doc.RootElement;
            return new SiteLocation(Num(r, "latitude"), Num(r, "longitude"), Str(r, "city"), Str(r, "country"));
        }
        catch (Exception ex)
        {
            _logger.LogDebug("Cannot read {Path}: {Error}", path, ex.Message);
            return null;
        }
    }

    // A service that returns the caller's own public-IP location directly. Several are tried in order (ipwho.is,
    // ipapi.co, …): free, no key, but rate-limited, so a fallback matters. Field names differ, so parsing is flexible.
    private SiteLocation? FromService()
    {
        foreach (var url in _options.LocationUrls)
        {
            if (string.IsNullOrWhiteSpace(url)) continue;
            try
            {
                using var resp = _http.GetAsync(url).GetAwaiter().GetResult();
                if (!resp.IsSuccessStatusCode) continue;
                using var doc = JsonDocument.Parse(resp.Content.ReadAsStringAsync().GetAwaiter().GetResult());
                var r = doc.RootElement;
                // Skip a service's own error payload (ipwho.is: success=false; ip-api.com: status="fail").
                if (r.TryGetProperty("success", out var ok) && ok.ValueKind == JsonValueKind.False) continue;
                if (Str(r, "status") == "fail" || Str(r, "error") == "true") continue;
                var lat = Num(r, "latitude") ?? Num(r, "lat");
                var lon = Num(r, "longitude") ?? Num(r, "lon");
                var city = Str(r, "city") ?? Str(r, "cityName");
                var country = Str(r, "country_name") ?? Str(r, "country") ?? Str(r, "countryName");
                if (lat is not null || city is not null) return new SiteLocation(lat, lon, city, country);
            }
            catch (Exception ex)
            {
                _logger.LogDebug("{Url} did not answer: {Error}", url, ex.Message);
            }
        }
        return null;
    }

    private static double? Num(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetDouble(out var d) ? d : null;

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    public void Dispose()
    {
        _timer.Dispose();
        _http.Dispose();
    }
}
