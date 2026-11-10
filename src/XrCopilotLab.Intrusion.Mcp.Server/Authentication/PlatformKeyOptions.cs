namespace XrCopilotLab.Intrusion.Mcp.Server.Authentication;

/// <summary>
/// The key that lets XRCopilotLab call this server. One configuration value is enough — <c>ApiKeys:Hash</c>, the
/// SHA-256 hex lowercase of the key. The clear key is kept by whoever registers the server in XRCopilotLab (Key Vault
/// for our deployments) and is never written here nor logged. The list form of the other MCP servers (<c>ApiKeys:Keys:n:Hash</c>, with <c>Id</c> and <c>Active</c>)
/// is still read for a second key during a rotation; <c>Id</c> and <c>Active</c> default to <c>platform</c> and
/// <c>true</c>, so they are never required in configuration.
/// </summary>
public sealed class ApiKeyOptions
{
    public const string SectionName = "ApiKeys";
    public const string HeaderName = "X-API-Key";

    public const string DefaultId = "platform";

    /// <summary>SHA-256 hex lowercase of the platform key (<c>ApiKeys:Hash</c>). The one value DevOps sets.</summary>
    public string? Hash { get; set; }

    /// <summary>Further keys, for a rotation: <c>ApiKeys:Keys:n:Hash</c> (and optionally <c>Id</c>, <c>Active</c>).</summary>
    public List<ApiKeyEntry> Keys { get; set; } = [];

    /// <summary>Every active key: the single hash first, then the list.</summary>
    public IEnumerable<ApiKeyEntry> ActiveKeys()
    {
        if (!string.IsNullOrWhiteSpace(Hash))
        {
            yield return new ApiKeyEntry { Id = DefaultId, Hash = Hash.Trim(), Active = true };
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
    public bool Active { get; set; } = true;
}
