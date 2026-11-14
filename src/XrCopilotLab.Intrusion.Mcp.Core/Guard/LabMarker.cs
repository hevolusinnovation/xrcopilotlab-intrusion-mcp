using System.Text.Json;

namespace XrCopilotLab.Intrusion.Mcp.Core.Guard;

/// <summary>
/// This host is the Docker lab's test server, not a customer's: only the lab's image writes the marker
/// (<c>/etc/xrcopilotlab-intrusion-mcp/lab.json</c>), never <c>install.sh</c>. Running in Docker says nothing: the
/// toolkit in a container on a VPS is a real server. <c>DemoVpnUsers</c>: VPN users the lab adds for its scenarios, whose
/// keys are given to the attacker on purpose. <c>Demo</c>: the rest that is there to be attacked (accounts with known
/// passwords, the sample site), one line each.
/// </summary>
public sealed record LabFacts(string Name, string Note, IReadOnlyList<string> DemoVpnUsers, IReadOnlyList<string> Demo);

public static class LabMarker
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true };

    /// <summary>The marker, or null when it is not valid JSON: a broken file must not hide the real host behind a lab.</summary>
    public static LabFacts? Parse(string json)
    {
        try
        {
            var m = JsonSerializer.Deserialize<Marker>(json, Json);
            return m is null ? null : new LabFacts(m.Name ?? "lab", m.Note ?? "", m.DemoVpnUsers ?? [], m.Demo ?? []);
        }
        catch (JsonException) { return null; }
    }

    private sealed record Marker(string? Name, string? Note, List<string>? DemoVpnUsers, List<string>? Demo);
}
