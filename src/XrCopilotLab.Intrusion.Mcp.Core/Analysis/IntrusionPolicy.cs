namespace XrCopilotLab.Intrusion.Mcp.Core.Analysis;

/// <summary>The judgement thresholds (<c>Policy:*</c>). The defaults suit a host whose users all work from Italy.</summary>
public sealed class IntrusionPolicy
{
    public const string SectionName = "Policy";

    /// <summary>ISO country codes a successful login is expected from. A login from elsewhere is reported.</summary>
    public List<string> AllowedCountries { get; set; } = ["IT"];

    /// <summary>Failures from the same address in the 24 hours before a successful login that make the login suspicious.</summary>
    public int FailuresBeforeLogin { get; set; } = 3;

    /// <summary>How many addresses, each trying one account a few times only, make a distributed campaign.</summary>
    public int CampaignMinIps { get; set; } = 8;

    /// <summary>At most this many failures per address for it to count as part of a campaign (under fail2ban's maxretry).</summary>
    public int CampaignMaxPerIp { get; set; } = 4;

    /// <summary>Distinct closed ports from one address in the period that make it a port scan.</summary>
    public int PortScanMinPorts { get; set; } = 10;

    /// <summary>Attempts from one address in the period that make it at least medium severity.</summary>
    public int MediumAttempts { get; set; } = 10;

    public bool IsAllowedCountry(string? code) =>
        code is null || AllowedCountries.Count == 0 || AllowedCountries.Contains(code, StringComparer.OrdinalIgnoreCase);
}
