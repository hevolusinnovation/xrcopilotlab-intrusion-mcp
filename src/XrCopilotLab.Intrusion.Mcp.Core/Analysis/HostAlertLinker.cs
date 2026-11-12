using XrCopilotLab.Intrusion.Mcp.Core.Models;
using XrCopilotLab.Intrusion.Mcp.Core.Parsing;

namespace XrCopilotLab.Intrusion.Mcp.Core.Analysis;

/// <summary>
/// Ties a Falco alert that has no address to the address that most likely caused it, so that "who got in" and "what
/// they did" end up in the same report. A process with <c>SSH_CLIENT</c> in its environment already has its address
/// (<see cref="Parsing.FalcoParser"/>); for the others:
/// <list type="bullet">
/// <item>a process below the web server (or run as <c>www-data</c>) → the address that sent a web exploit in the hour before (<c>web-exploit</c>);</item>
/// <item>otherwise the account that logged in (Falco's <c>user.loginname</c>, or <c>SUDO_USER</c> below sudo) → the
/// address of its last SSH login in the 12 hours before (<c>ssh-session</c>).</item>
/// </list>
/// An alert with neither stays without an address: it is reported for the host, not for an attacker.
/// </summary>
public static class HostAlertLinker
{
    public static readonly TimeSpan SessionWindow = TimeSpan.FromHours(12);
    public static readonly TimeSpan WebWindow = TimeSpan.FromHours(1);

    private static readonly string[] WebServers = ["nginx", "apache2", "httpd", "php-fpm", "lighttpd", "caddy", "uwsgi", "gunicorn"];
    private static readonly HashSet<string> WebUsers = new(StringComparer.Ordinal) { "www-data", "nginx", "apache", "http" };

    /// <param name="events">In time order, as the log sources return them.</param>
    public static IReadOnlyList<LogEvent> Link(IReadOnlyList<LogEvent> events)
    {
        if (!events.Any(e => e.Kind == LogEventKind.HostAlert && !e.HasAddress)) return events;

        var logins = events.Where(e => e.Kind == LogEventKind.AcceptedLogin && e.User is not null).ToList();
        var exploits = events.Where(IsWebExploit).ToList();
        var result = new List<LogEvent>(events.Count);
        foreach (var e in events)
        {
            if (e.Kind != LogEventKind.HostAlert || e.HasAddress) { result.Add(e); continue; }

            if (FromWeb(e) && exploits.LastOrDefault(x => x.Time <= e.Time && e.Time - x.Time <= WebWindow) is { } exploit)
                result.Add(e with { SourceIp = exploit.SourceIp, LinkedBy = "web-exploit" });
            else if (e.User is not null
                     && logins.LastOrDefault(l => l.User == e.User && l.Time <= e.Time && e.Time - l.Time <= SessionWindow) is { } login)
                result.Add(e with { SourceIp = login.SourceIp, LinkedBy = "ssh-session" });
            else
                result.Add(e);
        }
        return result;
    }

    private static bool FromWeb(LogEvent e) =>
        (e.User is not null && WebUsers.Contains(e.User))
        || (e.Parent ?? "").Split(" < ").Any(p => WebServers.Any(w => p.StartsWith(w, StringComparison.Ordinal)));

    private static bool IsWebExploit(LogEvent e) =>
        (e.Kind == LogEventKind.WebRequest && WebProbeRules.TypeOf(e.Rule!) == AttackType.WebExploitAttempt)
        || (e.Kind == LogEventKind.IdsAlert && AttackCatalog.FromIdsAlert(e) == AttackType.WebExploitAttempt);
}
