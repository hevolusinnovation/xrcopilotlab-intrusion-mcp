using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using XrCopilotLab.Intrusion.Mcp.Server.Collector;

namespace XrCopilotLab.Intrusion.Mcp.Server.Authentication;

/// <summary>
/// Validates the key in the <c>X-API-Key</c> header. Only the header: a key in the query string would end up in the
/// address of the MCP server, where every administrator of the workspace can read it. Two kinds of key: a read key
/// (XRCopilotLab, role <c>query</c>, one tenant) and an agent key (role <c>ingest</c>, one host, write only).
/// </summary>
public sealed class ApiKeyAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IOptionsMonitor<ApiKeyOptions> keys,
    IOptionsMonitor<CollectorOptions> collector)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "ApiKey";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string? provided = null;
        if (Request.Headers.TryGetValue(ApiKeyOptions.HeaderName, out var header) && !string.IsNullOrWhiteSpace(header))
            provided = header.ToString().Trim();

        if (provided is null)
            return Task.FromResult(AuthenticateResult.NoResult());

        var hash = HashHex(provided);
        Claim[]? claims = null;
        if (keys.CurrentValue.ActiveKeys().FirstOrDefault(k => Same(k.Hash, hash)) is { } read)
        {
            claims =
            [
                new Claim(ClaimTypes.NameIdentifier, read.Id), new Claim(KeyClaims.AgentId, read.Id),
                new Claim(KeyClaims.Tenant, read.Tenant), new Claim(KeyClaims.Role, KeyRoles.Query),
            ];
        }
        else if (collector.CurrentValue.ActiveHosts().FirstOrDefault(h => Same(h.IngestKeyHash, hash)) is { } host)
        {
            claims =
            [
                new Claim(ClaimTypes.NameIdentifier, $"{host.Tenant}/{host.Name}"), new Claim(KeyClaims.AgentId, $"{host.Tenant}/{host.Name}"),
                new Claim(KeyClaims.Tenant, host.Tenant), new Claim(KeyClaims.Host, host.Name), new Claim(KeyClaims.Role, KeyRoles.Ingest),
            ];
        }

        if (claims is null)
        {
            Logger.LogWarning("API key invalid (ip={IP})", Context.Connection.RemoteIpAddress);
            return Task.FromResult(AuthenticateResult.Fail("Invalid API key"));
        }

        var identity = new ClaimsIdentity(claims, SchemeName);
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = "ApiKey";
        return Task.CompletedTask;
    }

    public static string HashHex(string s) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(s)));

    private static bool Same(string? configured, string hash) =>
        configured is not null && string.Equals(configured.Trim(), hash, StringComparison.OrdinalIgnoreCase);
}

public static class KeyClaims
{
    public const string AgentId = "agent_id";
    public const string Tenant = "tenant";
    public const string Host = "host";
    public const string Role = "role";
}

public static class KeyRoles
{
    public const string Query = "query";
    public const string Ingest = "ingest";
}

public static class KeyPolicies
{
    public const string Query = "query";
    public const string Ingest = "ingest";
}
