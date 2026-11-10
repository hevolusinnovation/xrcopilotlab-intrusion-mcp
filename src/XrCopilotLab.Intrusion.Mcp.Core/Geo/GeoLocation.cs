namespace XrCopilotLab.Intrusion.Mcp.Core.Geo;

/// <summary>Where an address is. <see cref="Scope"/> says whether the other fields can be known at all.</summary>
public sealed record GeoLocation(
    string Scope,
    string? CountryCode = null,
    string? Country = null,
    string? City = null,
    double? Latitude = null,
    double? Longitude = null,
    string? Network = null)
{
    public const string Public = "public";
    public const string Private = "private";
    public const string Loopback = "loopback";
    public const string Documentation = "documentation";
    public const string Unknown = "unknown";

    public static GeoLocation Of(string scope) => new(scope);
}

/// <summary>Turns a source IP into a place.</summary>
public interface IGeoLocator
{
    GeoLocation Locate(string ip);

    /// <summary>The attribution the data's licence asks to show next to the results, if any.</summary>
    string? Attribution { get; }
}
