namespace XrCopilotLab.Intrusion.Mcp.Server;

/// <summary><c>Server:Mode</c>: <c>logs</c> reads the host's files, <c>simulated</c> the synthetic host of the demos.</summary>
public sealed class ServerOptions
{
    public const string SectionName = "Server";
    public const string Logs = "logs";
    public const string Simulated = "simulated";

    public string Mode { get; set; } = Logs;

    public bool IsSimulated => string.Equals(Mode, Simulated, StringComparison.OrdinalIgnoreCase);

    public void Validate()
    {
        if (!IsSimulated && !string.Equals(Mode, Logs, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Server:Mode '{Mode}' is not valid: expected '{Logs}' or '{Simulated}'.");
    }
}
