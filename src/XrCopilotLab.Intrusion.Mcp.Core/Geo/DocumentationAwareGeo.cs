using System.Net;
using XrCopilotLab.Intrusion.Mcp.Core.Simulation;

namespace XrCopilotLab.Intrusion.Mcp.Core.Geo;

/// <summary>
/// The collector's geography: documentation addresses (RFC 5737), which the simulated host and the Docker lab use, get
/// the invented places of <see cref="SyntheticGeo"/>; every other address goes to the real database, if there is one.
/// </summary>
public sealed class DocumentationAwareGeo(IGeoLocator real) : IGeoLocator
{
    private readonly SyntheticGeo _synthetic = new();

    public string? Attribution => real.Attribution is null
        ? _synthetic.Attribution
        : $"{real.Attribution} {_synthetic.Attribution}";

    public GeoLocation Locate(string ip) =>
        IPAddress.TryParse(ip, out var address) && IpScope.Classify(address) == GeoLocation.Documentation
            ? _synthetic.Locate(ip)
            : real.Locate(ip);
}
