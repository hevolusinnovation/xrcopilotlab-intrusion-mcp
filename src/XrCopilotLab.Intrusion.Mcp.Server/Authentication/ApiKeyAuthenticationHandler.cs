using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace XrCopilotLab.Intrusion.Mcp.Server.Authentication;

/// <summary>
/// Validates the key in the <c>X-API-Key</c> header. Only the header: a key in the query string would end up in the
/// address of the MCP server, where every administrator of the workspace can read it. Without the key, the logs of
/// the host would be readable by anyone who finds the address.
/// </summary>
public sealed class ApiKeyAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IOptionsMonitor<ApiKeyOptions> keys)
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
        var match = keys.CurrentValue.ActiveKeys().FirstOrDefault(k => string.Equals(k.Hash, hash, StringComparison.OrdinalIgnoreCase));
        if (match is null)
        {
            Logger.LogWarning("API key invalid (ip={IP})", Context.Connection.RemoteIpAddress);
            return Task.FromResult(AuthenticateResult.Fail("Invalid API key"));
        }

        var identity = new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, match.Id), new Claim("agent_id", match.Id)], SchemeName);
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = "ApiKey";
        return Task.CompletedTask;
    }

    public static string HashHex(string s) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(s)));
}
