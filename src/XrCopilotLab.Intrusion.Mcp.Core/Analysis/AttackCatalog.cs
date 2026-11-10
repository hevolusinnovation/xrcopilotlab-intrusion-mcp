using XrCopilotLab.Intrusion.Mcp.Core.Models;

namespace XrCopilotLab.Intrusion.Mcp.Core.Analysis;

/// <summary>
/// The attack type a fail2ban jail detects. The jail names are those of the filters shipped with fail2ban
/// (<c>/etc/fail2ban/filter.d</c>); a jail with another name is <see cref="AttackType.Other"/>.
/// </summary>
public static class AttackCatalog
{
    public const string SshJail = "sshd";
    public const string RecidiveJail = "recidive";

    public static AttackType FromJail(string jail) => jail.Trim().ToLowerInvariant() switch
    {
        "sshd" or "ssh" or "sshd-ddos" or "dropbear" => AttackType.SshBruteForce,
        "nginx-http-auth" or "apache-auth" or "lighttpd-auth" or "wordpress" or "drupal-auth" or "nextcloud" or "gitlab"
            or "grafana" or "phpmyadmin-syslog" or "roundcube-auth" => AttackType.WebLoginBruteForce,
        "nginx-botsearch" or "apache-botsearch" or "apache-noscript" or "apache-overflows" or "apache-nohome"
            or "apache-badbots" or "apache-fakegooglebot" or "php-url-fopen" or "nginx-bad-request" => AttackType.WebVulnerabilityScan,
        "nginx-limit-req" or "apache-modsecurity" => AttackType.RequestFlood,
        "postfix" or "postfix-sasl" or "dovecot" or "courier-auth" or "exim" or "sasl" => AttackType.MailLoginBruteForce,
        "recidive" => AttackType.RepeatOffender,
        _ => AttackType.Other,
    };

    /// <summary>Whether the jail's <c>Found</c> lines are attempts against a service (the recidive jail counts bans, not attempts).</summary>
    public static bool CountsAttempts(string jail) => !string.Equals(jail, RecidiveJail, StringComparison.OrdinalIgnoreCase);

    public static string Describe(AttackType type) => type switch
    {
        AttackType.SshBruteForce => "Repeated SSH login failures from one address.",
        AttackType.DistributedSshBruteForce => "The same SSH account tried from many addresses, each one staying under the ban threshold.",
        AttackType.WebLoginBruteForce => "Repeated failures on a web login.",
        AttackType.WebVulnerabilityScan => "Requests for pages that do not exist, looking for a vulnerable application.",
        AttackType.RequestFlood => "More requests than the rate limit allows: an attempt to overload the site.",
        AttackType.MailLoginBruteForce => "Repeated failures on a mail login.",
        AttackType.RepeatOffender => "An address banned several times that keeps coming back.",
        AttackType.LoginAfterFailures => "A successful SSH login right after repeated failures from the same address: possible compromise.",
        _ => "A fail2ban jail this server does not classify.",
    };
}
