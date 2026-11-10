namespace XrCopilotLab.Intrusion.Mcp.Core.Models;

/// <summary>What a log line says happened.</summary>
public enum LogEventKind
{
    /// <summary>fail2ban matched a failure of this IP in a jail (<c>[sshd] Found 203.0.113.7</c>).</summary>
    Found,

    /// <summary>fail2ban banned the IP in a jail.</summary>
    Ban,

    /// <summary>fail2ban lifted the ban.</summary>
    Unban,

    /// <summary>fail2ban restored a ban after a restart: the IP is still banned.</summary>
    RestoreBan,

    /// <summary>sshd refused a password or a key (<c>Failed password for … from …</c>).</summary>
    FailedLogin,

    /// <summary>sshd saw a user that does not exist (<c>Invalid user … from …</c>). The same attempt also logs a <see cref="FailedLogin"/>.</summary>
    InvalidUser,

    /// <summary>sshd let the user in (<c>Accepted password|publickey for … from …</c>).</summary>
    AcceptedLogin,
}

/// <summary>Which log the event comes from.</summary>
public enum LogOrigin
{
    Fail2ban,
    Auth,
}

/// <summary>One parsed log line about a source IP.</summary>
public sealed record LogEvent(
    DateTimeOffset Time,
    LogEventKind Kind,
    LogOrigin Origin,
    string SourceIp,
    string? Jail = null,
    string? User = null,
    int? Port = null,
    string? Method = null)
{
    public bool IsBanStart => Kind is LogEventKind.Ban or LogEventKind.RestoreBan;
}
