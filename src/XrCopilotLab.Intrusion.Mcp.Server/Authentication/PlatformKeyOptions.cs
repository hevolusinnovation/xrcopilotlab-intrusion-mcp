using XrCopilotLab.Intrusion.Mcp.Server.Collector;

namespace XrCopilotLab.Intrusion.Mcp.Server.Authentication;

/// <summary>
/// The keys that let XRCopilotLab read. One configuration value is enough — <c>ApiKeys:Hash</c>, the SHA-256 hex
/// lowercase of the key, for the tenant <c>ApiKeys:Tenant</c> (<c>default</c>). The clear key is kept by whoever
/// registers the server in XRCopilotLab (Key Vault for our deployments) and is never written here nor logged. Further
/// keys (<c>ApiKeys:Keys:n:Hash</c>, with optional <c>Id</c>, <c>Tenant</c>, <c>Active</c>) serve a rotation or another
/// tenant of the collector. A key reads only its own tenant's hosts.
/// </summary>
public sealed class ApiKeyOptions
{
    public const string SectionName = "ApiKeys";
    public const string HeaderName = "X-API-Key";

    public const string DefaultId = "platform";

    /// <summary>SHA-256 hex lowercase of the platform key (<c>ApiKeys:Hash</c>). The one value DevOps sets.</summary>
    public string? Hash { get; set; }

    /// <summary>The tenant of <see cref="Hash"/>.</summary>
    public string Tenant { get; set; } = TenantNames.Default;

    /// <summary>Further keys, for a rotation or another tenant: <c>ApiKeys:Keys:n:Hash</c> (and optionally <c>Id</c>, <c>Tenant</c>, <c>Active</c>).</summary>
    public List<ApiKeyEntry> Keys { get; set; } = [];

    /// <summary>Every active key: the single hash first, then the list.</summary>
    public IEnumerable<ApiKeyEntry> ActiveKeys()
    {
        if (!string.IsNullOrWhiteSpace(Hash))
        {
            yield return new ApiKeyEntry { Id = DefaultId, Hash = Hash.Trim(), Tenant = Tenant, Active = true };
        }
        foreach (var key in Keys)
        {
            if (key.Active && !string.IsNullOrWhiteSpace(key.Hash))
            {
                yield return key;
            }
        }
    }
}

public sealed class ApiKeyEntry
{
    public string Id { get; set; } = ApiKeyOptions.DefaultId;
    public string Hash { get; set; } = "";
    public string Tenant { get; set; } = TenantNames.Default;
    public bool Active { get; set; } = true;
}
