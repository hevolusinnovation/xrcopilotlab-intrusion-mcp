namespace XrCopilotLab.Intrusion.Mcp.Core.Guard;

/// <summary>
/// What the host says about its own protection, read without privileges: which guardians are installed and running,
/// in which mode, whether their logs reach the toolkit, which services listen on the network, how SSH is configured.
/// Gathered by an <see cref="IHostInspector"/>; judged by <see cref="PostureChecks"/>. <c>TunnelUrl</c>: the temporary public
/// address of a test tunnel (Dev Tunnels), when one is open (<see cref="ConnectionOptions.TunnelUrlFile"/>). <c>Vpn</c>:
/// the customer's WireGuard VPN and its users, when <c>install.sh --with wireguard</c> set it up.
/// </summary>
public sealed record HostFacts(
    DateTimeOffset Time,
    IReadOnlyList<GuardianFacts> Guardians,
    IReadOnlyList<ListeningPort> Listening,
    SshFacts? Ssh,
    string? TunnelUrl = null,
    VpnFacts? Vpn = null,
    LabFacts? Lab = null);

/// <summary>
/// One guardian: <c>fail2ban</c>, <c>crowdsec</c>, <c>suricata</c>, <c>falco</c>, <c>modsecurity</c>, <c>ufw</c>, the
/// VPN (<c>wireguard</c>, mode null: it neither watches nor blocks, it lets the customer's own people in), and
/// the services they protect (<c>sshd</c>, <c>nginx</c>). <c>Mode</c> is <c>detection</c> (it only reports),
/// <c>blocking</c> (it stops traffic) or null when it does not apply. <c>Managed</c>: configured by
/// <c>install.sh --with</c>. <c>LogReadable</c> is false when the log exists but the toolkit cannot open it.
/// </summary>
public sealed record GuardianFacts(
    string Name,
    bool Installed,
    string? Version,
    bool? Running,
    string? Mode,
    bool Managed,
    string? Log,
    bool LogExists,
    bool LogReadable,
    DateTimeOffset? LogUpdated,
    DateTimeOffset? RulesUpdated = null,
    string? Note = null);

/// <summary>A TCP port open to the network. <c>Public</c>: bound to every address or to one that is not loopback.</summary>
public sealed record ListeningPort(int Port, string Address, bool Public);

/// <summary>sshd's effective settings, from <c>sshd_config</c> and <c>sshd_config.d</c> (first value wins, as sshd reads them).
/// <c>Note</c>: files the toolkit could not read, whose settings are therefore not counted.</summary>
public sealed record SshFacts(bool PasswordAuthentication, string PermitRootLogin, int Port, string? Note = null);

/// <summary>Reads the host. A test or the simulated mode gives fixed facts.</summary>
public interface IHostInspector
{
    HostFacts Inspect(DateTimeOffset now);
}
