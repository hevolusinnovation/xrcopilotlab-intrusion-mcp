namespace XrCopilotLab.Intrusion.Mcp.Server;

/// <summary>
/// <c>Server:Mode</c>:
/// <list type="bullet">
/// <item><c>logs</c>: reads the files of the host it runs on, and XRCopilotLab calls it there;</item>
/// <item><c>simulated</c>: the synthetic host of the demos;</item>
/// <item><c>collector</c>: receives the lines that agents send (<c>POST /ingest</c>) and answers for every host of a
/// tenant, the simulated one included if configured. Nothing on the customer's side is open to the internet;</item>
/// <item><c>agent</c>: runs on the customer's host, reads its logs and sends the new lines to the collector. No web server.</item>
/// </list>
/// </summary>
public sealed class ServerOptions
{
    public const string SectionName = "Server";
    public const string Logs = "logs";
    public const string Simulated = "simulated";
    public const string Collector = "collector";
    public const string Agent = "agent";

    private static readonly string[] Modes = [Logs, Simulated, Collector, Agent];

    public string Mode { get; set; } = Logs;

    public bool IsSimulated => Is(Simulated);

    public bool IsCollector => Is(Collector);

    public bool IsAgent => Is(Agent);

    public bool Is(string mode) => string.Equals(Mode, mode, StringComparison.OrdinalIgnoreCase);

    public void Validate()
    {
        if (!Modes.Any(Is))
            throw new InvalidOperationException($"Server:Mode '{Mode}' is not valid: expected one of {string.Join(", ", Modes)}.");
    }
}
