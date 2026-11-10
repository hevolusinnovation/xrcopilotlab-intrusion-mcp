using System.Net;
using XrCopilotLab.Intrusion.Mcp.Core.Geo;

namespace XrCopilotLab.Intrusion.Mcp.Core.Simulation;

/// <summary>
/// The invented geography of the simulated mode. Every simulated address is in a documentation range (RFC 5737:
/// 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), which no real host uses, and gets a real city chosen by this table:
/// the place is invented, the coordinates are those of the city. Networks carry documentation AS numbers (RFC 5398).
/// </summary>
public sealed class SyntheticGeo : IGeoLocator
{
    public const string SimulatedAttribution = "Simulated data: documentation addresses (RFC 5737) with invented locations.";

    private static readonly Place[] Attackers =
    [
        new("CN", "China", "Shenzhen", 22.543, 114.058, "AS64500 Example Cloud"),
        new("CN", "China", "Beijing", 39.904, 116.407, "AS64501 Example Datacenter"),
        new("RU", "Russia", "Moscow", 55.756, 37.617, "AS64502 Example Hosting"),
        new("RU", "Russia", "Saint Petersburg", 59.934, 30.335, "AS64502 Example Hosting"),
        new("US", "United States", "Ashburn", 39.044, -77.487, "AS64503 Example Cloud Services"),
        new("US", "United States", "Dallas", 32.776, -96.797, "AS64504 Example Servers"),
        new("BR", "Brazil", "São Paulo", -23.551, -46.633, "AS64505 Example Telecom"),
        new("VN", "Vietnam", "Hanoi", 21.028, 105.854, "AS64506 Example Broadband"),
        new("IN", "India", "Mumbai", 19.076, 72.878, "AS64507 Example Networks"),
        new("KR", "South Korea", "Seoul", 37.567, 126.978, "AS64508 Example Internet"),
        new("NL", "Netherlands", "Amsterdam", 52.368, 4.904, "AS64509 Example VPS"),
        new("DE", "Germany", "Frankfurt am Main", 50.110, 8.682, "AS64503 Example Cloud Services"),
        new("RO", "Romania", "Bucharest", 44.427, 26.103, "AS64509 Example VPS"),
        new("ID", "Indonesia", "Jakarta", -6.208, 106.846, "AS64506 Example Broadband"),
        new("TR", "Türkiye", "Istanbul", 41.008, 28.978, "AS64505 Example Telecom"),
        new("UA", "Ukraine", "Kyiv", 50.450, 30.523, "AS64504 Example Servers"),
        new("IR", "Iran", "Tehran", 35.689, 51.389, "AS64507 Example Networks"),
        new("SG", "Singapore", "Singapore", 1.352, 103.820, "AS64500 Example Cloud"),
        new("HK", "Hong Kong SAR", "Hong Kong", 22.319, 114.169, "AS64501 Example Datacenter"),
        new("FR", "France", "Paris", 48.857, 2.352, "AS64509 Example VPS"),
    ];

    private static readonly Place[] Residential =
    [
        new("BR", "Brazil", "Recife", -8.048, -34.877, "AS64510 Example Home Broadband"),
        new("VN", "Vietnam", "Ho Chi Minh City", 10.823, 106.630, "AS64510 Example Home Broadband"),
        new("IN", "India", "Delhi", 28.614, 77.209, "AS64511 Example Mobile"),
        new("EG", "Egypt", "Cairo", 30.044, 31.236, "AS64511 Example Mobile"),
        new("PK", "Pakistan", "Karachi", 24.861, 67.010, "AS64510 Example Home Broadband"),
        new("TH", "Thailand", "Bangkok", 13.756, 100.502, "AS64511 Example Mobile"),
        new("MX", "Mexico", "Mexico City", 19.433, -99.133, "AS64510 Example Home Broadband"),
        new("AR", "Argentina", "Buenos Aires", -34.604, -58.382, "AS64511 Example Mobile"),
        new("NG", "Nigeria", "Lagos", 6.524, 3.379, "AS64511 Example Mobile"),
        new("PH", "Philippines", "Manila", 14.600, 120.984, "AS64510 Example Home Broadband"),
        new("CO", "Colombia", "Bogotá", 4.711, -74.072, "AS64510 Example Home Broadband"),
        new("MA", "Morocco", "Casablanca", 33.573, -7.590, "AS64511 Example Mobile"),
    ];

    private static readonly Place[] Hosting =
    [
        new("US", "United States", "Ashburn", 39.044, -77.487, "AS64503 Example Cloud Services"),
        new("NL", "Netherlands", "Amsterdam", 52.368, 4.904, "AS64509 Example VPS"),
        new("DE", "Germany", "Frankfurt am Main", 50.110, 8.682, "AS64503 Example Cloud Services"),
        new("FR", "France", "Roubaix", 50.690, 3.174, "AS64502 Example Hosting"),
        new("SG", "Singapore", "Singapore", 1.352, 103.820, "AS64500 Example Cloud"),
        new("US", "United States", "San Jose", 37.338, -121.886, "AS64504 Example Servers"),
        new("GB", "United Kingdom", "London", 51.507, -0.128, "AS64509 Example VPS"),
        new("CA", "Canada", "Montreal", 45.502, -73.567, "AS64502 Example Hosting"),
    ];

    private static readonly Place[] Italy =
    [
        new("IT", "Italy", "Bari", 41.117, 16.872, "AS64496 Example Business Fibre"),
        new("IT", "Italy", "Milan", 45.464, 9.190, "AS64497 Example Mobile Italia"),
        new("IT", "Italy", "Rome", 41.903, 12.496, "AS64496 Example Business Fibre"),
    ];

    private static readonly Place Incident = new("MD", "Moldova", "Chișinău", 47.011, 28.863, "AS64499 Example Bulletproof VPS");

    public string? Attribution => SimulatedAttribution;

    public GeoLocation Locate(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address)) return GeoLocation.Of(GeoLocation.Unknown);
        var scope = IpScope.Classify(address);
        if (scope != GeoLocation.Documentation) return GeoLocation.Of(scope);

        var b = address.MapToIPv4().GetAddressBytes();
        var last = b[3];
        var place = (b[0], b[1], b[2]) switch
        {
            (203, 0, 113) => Attackers[last * 7 % Attackers.Length],
            (192, 0, 2) => Residential[last * 5 % Residential.Length],
            (198, 51, 100) when last < SyntheticHost.LegitimateTop => Italy[last % Italy.Length],
            (198, 51, 100) when last == SyntheticHost.IncidentOctet => Incident,
            (198, 51, 100) => Hosting[last * 3 % Hosting.Length],
            _ => null,
        };
        return place is null
            ? GeoLocation.Of(GeoLocation.Documentation)
            : new GeoLocation(GeoLocation.Public, place.Code, place.Country, place.City, place.Lat, place.Lon, place.Network);
    }

    private sealed record Place(string Code, string Country, string City, double Lat, double Lon, string Network);
}
