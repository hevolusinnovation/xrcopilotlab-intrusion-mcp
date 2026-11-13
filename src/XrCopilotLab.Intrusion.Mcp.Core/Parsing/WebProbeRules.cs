using System.Text.RegularExpressions;
using XrCopilotLab.Intrusion.Mcp.Core.Models;

namespace XrCopilotLab.Intrusion.Mcp.Core.Parsing;

/// <summary>
/// The patterns that make a web request an attack, in order: exploits first (they say more), then the scans for known
/// paths, then the scanner user agents, then the status codes of a refused login and of the rate limit, then text written
/// for an AI (<see cref="UntrustedText.Injection"/>). A request that matches none is ordinary traffic and is not kept.
/// </summary>
public static partial class WebProbeRules
{
    private static readonly (string Rule, AttackType Type, Regex Pattern)[] PathRules =
    [
        ("log4shell", AttackType.WebExploitAttempt, Log4Shell()),
        ("path-traversal", AttackType.WebExploitAttempt, Traversal()),
        ("sql-injection", AttackType.WebExploitAttempt, SqlInjection()),
        ("command-injection", AttackType.WebExploitAttempt, CommandInjection()),
        ("phpunit-rce", AttackType.WebExploitAttempt, PhpUnit()),
        ("env-file", AttackType.WebVulnerabilityScan, EnvFile()),
        ("git-repository", AttackType.WebVulnerabilityScan, GitRepo()),
        ("wordpress", AttackType.WebVulnerabilityScan, WordPress()),
        ("phpmyadmin", AttackType.WebVulnerabilityScan, PhpMyAdmin()),
        ("admin-console", AttackType.WebVulnerabilityScan, AdminConsole()),
        ("backup-file", AttackType.WebVulnerabilityScan, BackupFile()),
        ("web-shell", AttackType.WebVulnerabilityScan, WebShell()),
        ("cgi-bin", AttackType.WebVulnerabilityScan, CgiBin()),
    ];

    /// <summary>A request whose only sign of attack is text written for the AI that reads the logs.</summary>
    public const string PromptInjectionRule = "prompt-injection";

    /// <summary>The rule a request matches, or null for ordinary traffic.</summary>
    public static (string Rule, AttackType Type)? Match(string path, int status, string? userAgent)
    {
        var decoded = UntrustedText.Decode(path);
        foreach (var (rule, type, pattern) in PathRules)
            if (pattern.IsMatch(decoded)) return (rule, type);
        if (userAgent is not null && Log4Shell().IsMatch(userAgent)) return ("log4shell", AttackType.WebExploitAttempt);
        if (userAgent is not null && ScannerAgent().IsMatch(userAgent)) return ("scanner-agent", AttackType.WebVulnerabilityScan);
        if (status == 401) return ("auth-failure", AttackType.WebLoginBruteForce);
        if (status == 429) return ("rate-limited", AttackType.RequestFlood);
        if (Injection(path, userAgent) is not null) return (PromptInjectionRule, AttackType.AiPromptInjection);
        return null;
    }

    public static AttackType TypeOf(string rule)
    {
        foreach (var (r, type, _) in PathRules)
            if (r == rule) return type;
        return rule switch
        {
            "scanner-agent" => AttackType.WebVulnerabilityScan,
            "auth-failure" => AttackType.WebLoginBruteForce,
            "rate-limited" => AttackType.RequestFlood,
            PromptInjectionRule => AttackType.AiPromptInjection,
            _ => AttackType.Other,
        };
    }

    /// <summary>The prompt-injection rule the path (decoded) or the user agent matches, or null.</summary>
    public static string? Injection(string path, string? userAgent) =>
        UntrustedText.Injection(UntrustedText.Decode(path)) ?? UntrustedText.Injection(userAgent);

    [GeneratedRegex(@"\$\{\s*jndi\s*:", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Log4Shell();

    [GeneratedRegex(@"\.\./|\.\.\\|/etc/passwd|win\.ini", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Traversal();

    [GeneratedRegex(@"union[\s(]+(all\s+)?select|'\s*or\s*'?\d'?\s*=\s*'?\d|sleep\(\d+\)|information_schema", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SqlInjection();

    [GeneratedRegex(@"[;|`]\s*(wget|curl|sh|bash|nc)\b|\$\((wget|curl)|/bin/(ba)?sh", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CommandInjection();

    [GeneratedRegex(@"/vendor/phpunit/.*eval-stdin\.php", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PhpUnit();

    [GeneratedRegex(@"/\.env(\.|$|\?)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex EnvFile();

    [GeneratedRegex(@"/\.git/", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex GitRepo();

    [GeneratedRegex(@"wp-login\.php|/wp-admin|xmlrpc\.php|/wp-content/|/wp-includes/", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex WordPress();

    [GeneratedRegex(@"/(phpmyadmin|pma|myadmin)/", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PhpMyAdmin();

    [GeneratedRegex(@"/(actuator|server-status|manager/html|solr/admin|_profiler|telescope|hnap1|boaform)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AdminConsole();

    [GeneratedRegex(@"\.(bak|old|sql|sql\.gz|tar\.gz|zip|swp)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BackupFile();

    [GeneratedRegex(@"/(shell|cmd|c99|r57|wso|alfa)\.php", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex WebShell();

    [GeneratedRegex(@"/cgi-bin/", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CgiBin();

    [GeneratedRegex(@"sqlmap|nikto|nuclei|zgrab|masscan|nmap|gobuster|dirbuster|wpscan|acunetix|nessus", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ScannerAgent();
}
