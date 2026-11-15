using XrCopilotLab.Intrusion.Mcp.Core.Analysis;
using XrCopilotLab.Intrusion.Mcp.Core.Geo;
using XrCopilotLab.Intrusion.Mcp.Core.Guard;
using XrCopilotLab.Intrusion.Mcp.Core.Models;
using XrCopilotLab.Intrusion.Mcp.Core.Queries;
using XrCopilotLab.Intrusion.Mcp.Core.Simulation;
using XrCopilotLab.Intrusion.Mcp.Core.Sources;
using Xunit;

namespace XrCopilotLab.Intrusion.Mcp.Core.Tests;

/// <summary>
/// Only the lab's marker makes a host "the lab": the toolkit in a container, on a VPS or on a Docker network, is a real
/// server and must answer as one.
/// </summary>
public class LabMarkerTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 14, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void The_lab_images_marker_is_valid()
    {
        var lab = LabMarker.Parse(File.ReadAllText(Path.Combine(RepoRoot(), "lab/server/files/etc/xrcopilotlab-intrusion-mcp/lab.json")));
        Assert.NotNull(lab);
        Assert.Equal("lab-01", lab.Name);
        Assert.Contains("anna-portatile", lab.DemoVpnUsers);
        Assert.NotEmpty(lab.Demo);
    }

    [Theory]
    [InlineData("")]
    [InlineData("{\"name\":")]
    public void A_broken_marker_is_no_lab(string text) => Assert.Null(LabMarker.Parse(text));

    [Fact]
    public void With_the_marker_the_page_and_the_posture_say_it_is_the_lab()
    {
        var lab = new LabFacts("lab-01", "test server", ["anna-portatile", "gone-user"], ["operatore has a known password"]);
        var queries = Queries(new MarkedInspector(lab));

        Assert.Equal(lab, queries.Guardians(Now).Lab);
        var vpn = queries.Vpn(Now);
        Assert.True(vpn.Peers.Single(p => p.Name == "anna-portatile").LabDemo);
        Assert.False(vpn.Peers.Single(p => p.Name == "mario-telefono").LabDemo);

        var finding = queries.Posture(Now, new Period(Now.AddDays(-7), Now)).Findings[0];
        Assert.Equal("lab-image", finding.Id);
        Assert.Equal(nameof(Severity.Critical), finding.Severity);
        Assert.Contains("anna-portatile", finding.Evidence);
        Assert.DoesNotContain("gone-user", finding.Evidence);   // revoked already: only what is still there is reported
        Assert.Contains("operatore has a known password", finding.Evidence);
        Assert.Equal("sudo xrc-vpn revoke anna-portatile", finding.Fix);
    }

    [Fact]
    public void Without_the_marker_it_is_a_real_server_even_with_the_same_users()
    {
        var queries = Queries(new SimulatedHostInspector());

        Assert.Null(queries.Guardians(Now).Lab);
        Assert.DoesNotContain(queries.Vpn(Now).Peers, p => p.LabDemo);
        Assert.DoesNotContain(queries.Posture(Now, new Period(Now.AddDays(-7), Now)).Findings, f => f.Id == "lab-image");
    }

    private static GuardQueries Queries(IHostInspector inspector) =>
        new(inspector, new IntrusionQueries(new EmptySource(), new NoGeoLocator(), new IntrusionPolicy()), new FixedSite(), new ConnectionOptions(),
            new SyntheticGeo(), new IntrusionPolicy());

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (Directory.Exists(Path.Combine(dir.FullName, "lab", "server", "files"))) return dir.FullName;
        throw new DirectoryNotFoundException("repository root not found");
    }

    private sealed class MarkedInspector(LabFacts lab) : IHostInspector
    {
        public HostFacts Inspect(DateTimeOffset now) => new SimulatedHostInspector().Inspect(now) with { Lab = lab };
    }

    private sealed class FixedSite : ISiteLocation
    {
        public SiteLocation Current => new();
    }

    private sealed class EmptySource : ILogSource
    {
        public string Hostname => "lab-01";
        public bool Simulated => false;
        public int MaxDays => 30;
        public IReadOnlyList<string> Describe() => [];
        public IReadOnlyList<LogEvent> Read(DateTimeOffset since, DateTimeOffset now) => [];
    }
}
