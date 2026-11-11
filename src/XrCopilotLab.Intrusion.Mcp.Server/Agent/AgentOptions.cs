using XrCopilotLab.Intrusion.Mcp.Core.Sources;

namespace XrCopilotLab.Intrusion.Mcp.Server.Agent;

/// <summary>Settings of the agent mode (<c>Agent:*</c>), on the customer's host.</summary>
public sealed class AgentOptions
{
    public const string SectionName = "Agent";

    /// <summary>The collector, e.g. <c>https://hev-intrusion-mcp.…azurecontainerapps.io/</c>. Only outbound HTTPS to it is needed.</summary>
    public string CollectorUrl { get; set; } = "";

    /// <summary>The host's agent key (<c>Agent__Key</c> in the systemd environment file). Never logged.</summary>
    public string? Key { get; set; }

    /// <summary>The host's time zone (IANA id); empty = the system zone. fail2ban writes local time without an offset.</summary>
    public string? TimeZone { get; set; }

    public int IntervalSeconds { get; set; } = 10;

    /// <summary>At most this much of a file per round; the rest goes in the next one, right after.</summary>
    public int MaxBytesPerRead { get; set; } = 2 * 1024 * 1024;

    /// <summary>On the first run, how much of the end of each file to send: the recent history, not years of it.</summary>
    public long InitialBackfillBytes { get; set; } = 8 * 1024 * 1024;

    /// <summary>Where the agent remembers how far it read each file (systemd <c>StateDirectory</c>).</summary>
    public string StateFile { get; set; } = "/var/lib/xrcopilotlab-intrusion-agent/state.json";

    /// <summary>The current file of each log (<see cref="LogNames"/>); an empty path turns that log off. Rotated copies
    /// are read only to finish a file that rotated between two rounds.</summary>
    public Dictionary<string, string> Files { get; set; } = new(StringComparer.Ordinal)
    {
        [LogNames.Fail2ban] = "/var/log/fail2ban.log",
        [LogNames.Auth] = "/var/log/auth.log",
        [LogNames.Firewall] = "/var/log/ufw.log",
        [LogNames.WebAccess] = "/var/log/nginx/access.log",
        [LogNames.Crowdsec] = "/var/log/crowdsec.log",
    };

    public void Validate()
    {
        if (!Uri.TryCreate(CollectorUrl, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
            throw new InvalidOperationException("Agent:CollectorUrl must be the collector's address (https://…).");
        if (string.IsNullOrWhiteSpace(Key))
            throw new InvalidOperationException("Agent:Key is not set (Agent__Key in the environment file).");
        foreach (var name in Files.Keys)
            if (!LogNames.IsKnown(name)) throw new InvalidOperationException($"Agent:Files:{name}: unknown log, expected one of {string.Join(", ", LogNames.All)}.");
    }
}
