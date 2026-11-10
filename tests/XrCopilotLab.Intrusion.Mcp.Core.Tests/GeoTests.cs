using System.Net;
using XrCopilotLab.Intrusion.Mcp.Core.Geo;
using XrCopilotLab.Intrusion.Mcp.Core.Simulation;
using Xunit;

namespace XrCopilotLab.Intrusion.Mcp.Core.Tests;

public class GeoTests
{
    [Theory]
    [InlineData("10.20.1.5", GeoLocation.Private)]
    [InlineData("192.168.4.1", GeoLocation.Private)]
    [InlineData("172.20.0.1", GeoLocation.Private)]
    [InlineData("127.0.0.1", GeoLocation.Loopback)]
    [InlineData("203.0.113.7", GeoLocation.Documentation)]
    [InlineData("2001:db8::1", GeoLocation.Documentation)]
    [InlineData("8.8.8.8", GeoLocation.Public)]
    [InlineData("2a00:1450:4002::1", GeoLocation.Public)]
    public void Classifies_reserved_ranges(string ip, string scope) =>
        Assert.Equal(scope, IpScope.Classify(IPAddress.Parse(ip)));

    [Fact]
    public void Reads_a_dbip_city_lite_row_and_finds_the_range()
    {
        Assert.True(IpRangeGeoTable.TryParseDbIpCityRow("8.8.8.0,8.8.8.255,NA,US,California,\"Mountain View\",37.4223,-122.085", out var row));
        var table = new IpRangeGeoTable([row], "attribution");

        var hit = table.Locate("8.8.8.8");
        Assert.Equal(("US", "Mountain View", 37.4223), (hit.CountryCode, hit.City, hit.Latitude));
        Assert.Equal(GeoLocation.Public, table.Locate("8.8.9.1").Scope);
        Assert.Null(table.Locate("8.8.9.1").CountryCode);
        Assert.Equal(GeoLocation.Private, table.Locate("10.0.0.1").Scope);
    }

    [Fact]
    public void Simulated_addresses_have_an_invented_place()
    {
        var geo = new SyntheticGeo();
        var incident = geo.Locate(SyntheticHost.IncidentIp);
        Assert.Equal("MD", incident.CountryCode);
        Assert.NotNull(incident.Latitude);
        Assert.Equal("IT", geo.Locate(SyntheticHost.OfficeIp).CountryCode);
        Assert.Equal(GeoLocation.Private, geo.Locate("10.0.0.1").Scope);
        Assert.Equal(GeoLocation.Public, geo.Locate("203.0.113.40").Scope);
    }
}
