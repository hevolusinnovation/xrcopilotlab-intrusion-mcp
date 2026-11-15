using XrCopilotLab.Intrusion.Mcp.Core.Analysis;
using XrCopilotLab.Intrusion.Mcp.Core.Geo;
using XrCopilotLab.Intrusion.Mcp.Core.Guard;
using XrCopilotLab.Intrusion.Mcp.Core.Models;
using XrCopilotLab.Intrusion.Mcp.Core.Parsing;
using XrCopilotLab.Intrusion.Mcp.Core.Queries;
using XrCopilotLab.Intrusion.Mcp.Core.Simulation;
using XrCopilotLab.Intrusion.Mcp.Core.Sources;
using Xunit;

namespace XrCopilotLab.Intrusion.Mcp.Core.Tests;

/// <summary>
/// The toolkit as a guardian of the customer's own AI: the search for exposed AI services, prompt injection in what is
/// sent to a chatbot (ModSecurity, install.sh's rules 2001xx), and an AI service open to the network.
/// </summary>
public class AiGuardianTests
{
    private static readonly TimeZoneInfo Rome = TimeZoneInfo.FindSystemTimeZoneById("Europe/Rome");
    private static readonly DateTimeOffset Now = new(2026, 11, 10, 14, 0, 0, TimeSpan.FromHours(1));

    // What install.sh's rule 200101 writes, as ModSecurity v3 logged it in a test container (nginx, CRS 3.3.5).
    private const string ChatInjection = """{"transaction":{"client_ip":"203.0.113.30","time_stamp":"Fri Nov 13 21:19:21 2026","client_port":51544,"host_ip":"10.30.0.15","host_port":80,"request":{"method":"POST","http_version":1.1,"uri":"/v1/chat/completions"},"response":{"http_code":404},"producer":{"modsecurity":"ModSecurity v3.0.12 (Linux)","secrules_engine":"DetectionOnly"},"messages":[{"message":"AI prompt injection: instruction-override","details":{"ruleId":"200101","severity":"2","tags":["attack-prompt-injection","xrcopilotlab"]}},{"message":"Inbound Anomaly Score Exceeded (Total Score: 5)","details":{"ruleId":"949110","severity":"2","tags":["application-multi","language-multi","platform-multi","attack-generic"]}}]}}""";

    [Theory]
    [InlineData("/api/tags", 404)]
    [InlineData("/v1/models", 404)]
    [InlineData("/v1/chat/completions", 401)]
    [InlineData("/mcp", 401)]
    [InlineData("/.well-known/mcp", 404)]
    [InlineData("/gradio_api/info", 404)]
    public void A_refused_or_missing_ai_path_is_a_search_for_ai_services(string path, int status) =>
        Assert.Equal((WebProbeRules.AiEndpointRule, AttackType.AiServiceProbe), WebProbeRules.Match(path, status, "python-httpx/0.27.0"));

    [Theory]
    [InlineData("/api/chat", 200)]
    [InlineData("/v1/chat/completions", 200)]
    [InlineData("/api/tagsfoo", 404)]
    [InlineData("/blog/api/tags", 404)]
    public void A_site_that_really_serves_ai_or_another_path_is_not_a_probe(string path, int status) =>
        Assert.NotEqual(WebProbeRules.AiEndpointRule, WebProbeRules.Match(path, status, "Mozilla/5.0")?.Rule);

    [Fact]
    public void The_ai_ports_have_names()
    {
        Assert.Equal("Ollama", AttackCatalog.ServiceOf(11434));
        Assert.StartsWith("Qdrant", AttackCatalog.ServiceOf(6333), StringComparison.Ordinal);
    }

    [Fact]
    public void Text_for_an_ai_in_a_chatbot_message_is_read_from_the_waf()
    {
        Assert.True(ModSecurityParser.TryParse(ChatInjection, Rome, out var e));
        Assert.Equal("prompt-injection", ModSecurityParser.FamilyOf(e!));
        Assert.Equal(AttackType.AiPromptInjection, ModSecurityParser.TypeOf(e!));
        Assert.Equal("instruction-override", e!.Injection);
        // The body is not in the log: the evidence is where it was sent.
        Assert.Equal("body", ThreatAnalyzer.InjectionField(e));
        Assert.Equal("/v1/chat/completions", e.Path);
    }

    [Fact]
    public void An_injection_with_an_exploit_stays_an_exploit_and_is_still_seen()
    {
        var line = ChatInjection.Replace(
            """{"message":"AI prompt injection""",
            """{"message":"SQL Injection Attack Detected via libinjection","details":{"ruleId":"942100","severity":"2","tags":["attack-sqli"]}},{"message":"AI prompt injection""",
            StringComparison.Ordinal);
        Assert.True(ModSecurityParser.TryParse(line, Rome, out var e));
        Assert.Equal(AttackType.WebExploitAttempt, ModSecurityParser.TypeOf(e!));
        Assert.Equal("instruction-override", e!.Injection);
    }

    [Fact]
    public void The_simulated_ai_scanner_and_form_injection_are_reported()
    {
        var q = new IntrusionQueries(new SimulatedLogSource(new SimulationOptions()), new SyntheticGeo(), new IntrusionPolicy());
        var period = q.Resolve(Now, 48, null, null);

        var scanner = q.IpDetail(Now, period, SyntheticHost.AiScannerIp).Report!;
        Assert.Contains(nameof(AttackType.AiServiceProbe), scanner.AttackTypes);
        Assert.Contains(scanner.PortsProbed, p => p.Port == 11434 && p.Service == "Ollama");
        Assert.Contains(scanner.WebProbes, w => w.Rule == WebProbeRules.AiEndpointRule);

        var form = q.IpDetail(Now, period, SyntheticHost.FormInjectionIp).Report!;
        Assert.Contains(nameof(AttackType.AiPromptInjection), form.AttackTypes);
        Assert.Contains(form.PromptInjections, p => p.Field == "body" && p.Rule == "instruction-override");
        Assert.True(Enum.Parse<Severity>(form.Severity) >= Severity.High);
    }

    [Fact]
    public void Ollama_open_to_the_network_is_a_finding_and_on_localhost_is_not()
    {
        var q = new IntrusionQueries(new SimulatedLogSource(new SimulationOptions()), new SyntheticGeo(), new IntrusionPolicy());
        var attacks = q.Summary(Now, q.Resolve(Now, 168, null, null), 100);
        GuardianFacts G(string name, string? mode = null) => new(name, true, "1.0", true, mode, false, $"/var/log/{name}.log", true, true, Now, Now.AddHours(-8));
        GuardianFacts[] guardians = [G("sshd"), G("nginx"), G("ufw", "blocking"), G("fail2ban", "blocking"), G("modsecurity", "detection")];
        HostFacts Facts(params ListeningPort[] ports) => new(Now, guardians, [new(22, "0.0.0.0", true), .. ports], new SshFacts(false, "prohibit-password", 22));

        var open = PostureChecks.Evaluate(Facts(new ListeningPort(11434, "0.0.0.0", true)), attacks);
        var ollama = Assert.Single(open, f => f.Id == "exposed-ai-11434");
        Assert.Equal(nameof(Severity.High), ollama.Severity);
        Assert.Contains("OLLAMA_HOST=127.0.0.1", ollama.Recommendation, StringComparison.Ordinal);
        Assert.Contains(open, f => f.Id == "ai-probes");
        Assert.Contains(open, f => f.Id == "ai-prompt-injection");

        var local = PostureChecks.Evaluate(Facts(new ListeningPort(11434, "127.0.0.1", false)), attacks);
        Assert.DoesNotContain(local, f => f.Id.StartsWith("exposed-ai-", StringComparison.Ordinal));
    }
}
