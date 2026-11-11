namespace XrCopilotLab.Intrusion.Mcp.Server.Collector;

/// <summary>Settings of the collector mode (<c>Collector:*</c>).</summary>
public sealed class CollectorOptions
{
    public const string SectionName = "Collector";
    public const string FileStore = "file";
    public const string BlobStore = "blob";

    /// <summary><c>file</c> (a folder: the Docker lab, tests) or <c>blob</c> (Azure append blobs).</summary>
    public string Store { get; set; } = FileStore;

    /// <summary>Folder of the file store.</summary>
    public string StorePath { get; set; } = "/data/intrusion";

    /// <summary>Connection string of the storage account (a Container App secret), for the blob store.</summary>
    public string? BlobConnectionString { get; set; }

    public string BlobContainer { get; set; } = "intrusion-events";

    /// <summary>Days of events kept; older files are deleted.</summary>
    public int RetentionDays { get; set; } = 30;

    /// <summary>Tenants that also see the simulated host (<c>Simulation:Hostname</c>) next to their real ones.</summary>
    public List<string> SimulatedTenants { get; set; } = [];

    /// <summary>The hosts allowed to send, each with its own key: <c>Collector:Hosts:n:Name|Tenant|IngestKeyHash</c>.</summary>
    public List<HostRegistration> Hosts { get; set; } = [];

    public IEnumerable<HostRegistration> ActiveHosts() =>
        Hosts.Where(h => h.Active && !string.IsNullOrWhiteSpace(h.Name) && !string.IsNullOrWhiteSpace(h.IngestKeyHash));
}

/// <summary>
/// A host whose agent may send lines. The key only writes, and only for this host: a key stolen from a compromised
/// host cannot read anything, nor write in the name of another host. Revoking it is <c>Active = false</c>.
/// </summary>
public sealed class HostRegistration
{
    public string Name { get; set; } = "";
    public string Tenant { get; set; } = TenantNames.Default;

    /// <summary>SHA-256 hex lowercase of the agent's key.</summary>
    public string IngestKeyHash { get; set; } = "";

    public bool Active { get; set; } = true;
}

public static class TenantNames
{
    public const string Default = "default";
}
