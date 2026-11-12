using System.IO.Compression;
using System.Net.NetworkInformation;
using XrCopilotLab.Intrusion.Mcp.Core.Models;
using XrCopilotLab.Intrusion.Mcp.Core.Sources;

namespace XrCopilotLab.Intrusion.Mcp.Server.Sources;

/// <summary>Settings of the real mode (<c>Logs:*</c>): which files to read on the host.</summary>
public sealed class LogFileOptions
{
    public const string SectionName = "Logs";

    /// <summary>Host name to show; empty = the machine name.</summary>
    public string? Hostname { get; set; }

    /// <summary>The host's time zone (IANA id); empty = the system zone. fail2ban writes local time without an offset.</summary>
    public string? TimeZone { get; set; }

    /// <summary>fail2ban logs. A <c>*</c> in the file name takes the rotated copies too (<c>.1</c>, <c>.2.gz</c>…).</summary>
    public List<string> Fail2banFiles { get; set; } = ["/var/log/fail2ban.log*"];

    /// <summary>sshd logs (Debian and Ubuntu: auth.log; RHEL: secure).</summary>
    public List<string> AuthFiles { get; set; } = ["/var/log/auth.log*"];

    /// <summary>UFW logs (<c>ufw logging low</c>): the connections to closed ports.</summary>
    public List<string> FirewallFiles { get; set; } = ["/var/log/ufw.log*"];

    /// <summary>nginx access logs, <c>combined</c> format. Only the requests that match an attack pattern are kept.</summary>
    public List<string> WebAccessFiles { get; set; } = ["/var/log/nginx/access.log*"];

    /// <summary>CrowdSec logs: alerts and decisions.</summary>
    public List<string> CrowdsecFiles { get; set; } = ["/var/log/crowdsec.log*"];

    /// <summary>Suricata EVE logs: only its alerts are read (<c>event_type: alert</c>, severity 1 and 2).</summary>
    public List<string> SuricataFiles { get; set; } = ["/var/log/suricata/eve.json*"];

    /// <summary>Falco JSON file output (<c>json_output: true</c>): what processes did on the host. <c>install.sh --with falco</c> writes it here.</summary>
    public List<string> FalcoFiles { get; set; } = ["/var/log/falco/events.json*"];

    /// <summary>
    /// The host's own addresses, to tell an attack coming in from a connection the host opened (a Suricata alert on
    /// malware calling home). Empty = the addresses of the host's network interfaces.
    /// </summary>
    public List<string> LocalAddresses { get; set; } = [];

    /// <summary>How many days back to read.</summary>
    public int MaxDays { get; set; } = 30;
}

/// <summary>
/// The real mode: reads the host's log files at every call, so nothing is kept and nothing is written. The account
/// the server runs as must be able to read them (on Ubuntu: group <c>adm</c>). A log the host does not have is skipped.
/// </summary>
public sealed class FileLogSource(LogFileOptions options, ILogger<FileLogSource> logger) : ILogSource
{
    private readonly TimeZoneInfo _zone = string.IsNullOrWhiteSpace(options.TimeZone)
        ? TimeZoneInfo.Local
        : TimeZoneInfo.FindSystemTimeZoneById(options.TimeZone);

    public string Hostname => string.IsNullOrWhiteSpace(options.Hostname) ? Environment.MachineName : options.Hostname;

    public bool Simulated => false;

    public int MaxDays => options.MaxDays;

    public IReadOnlyList<string> Describe() =>
        AllPatterns().SelectMany(Expand).DefaultIfEmpty("no log file found: check the Logs:*Files settings").ToList();

    private IEnumerable<List<string>> AllPatterns() =>
        [options.Fail2banFiles, options.AuthFiles, options.FirewallFiles, options.WebAccessFiles, options.CrowdsecFiles, options.SuricataFiles, options.FalcoFiles];

    private IReadOnlySet<string>? _local;

    // Read once: the host's addresses do not change while the service runs.
    private IReadOnlySet<string> Local => _local ??= options.LocalAddresses.Count > 0
        ? options.LocalAddresses.ToHashSet(StringComparer.Ordinal)
        : InterfaceAddresses();

    private HashSet<string> InterfaceAddresses()
    {
        try
        {
            var addresses = NetworkInterface.GetAllNetworkInterfaces()
                .SelectMany(n => n.GetIPProperties().UnicastAddresses)
                .Select(a => a.Address.ToString())
                .ToHashSet(StringComparer.Ordinal);
            if (addresses.Count == 0) logger.LogWarning("No address found on the host's interfaces: set Logs:LocalAddresses");
            return addresses;
        }
        catch (Exception ex) when (ex is NetworkInformationException or PlatformNotSupportedException or IOException)
        {
            logger.LogWarning("Cannot list the host's addresses ({Error}): set Logs:LocalAddresses", ex.Message);
            return [];
        }
    }

    public IReadOnlyList<LogEvent> Read(DateTimeOffset since, DateTimeOffset now)
    {
        var floor = now.AddDays(-options.MaxDays);
        if (since < floor) since = floor;

        var logs = new LogSet(
            Lines(options.Fail2banFiles, since),
            Lines(options.AuthFiles, since),
            Lines(options.FirewallFiles, since),
            Lines(options.WebAccessFiles, since),
            Lines(options.CrowdsecFiles, since),
            Lines(options.SuricataFiles, since),
            Lines(options.FalcoFiles, since));
        var events = LogLines.Parse(logs, _zone, now, Local)
            .Where(e => e.Time >= since && e.Time <= now)
            .ToList();
        events.Sort((a, b) => a.Time.CompareTo(b.Time));
        return events;
    }

    private IEnumerable<string> Lines(IEnumerable<string> patterns, DateTimeOffset since)
    {
        foreach (var path in Expand(patterns))
        {
            // A rotated file older than the period has nothing to say.
            if (File.GetLastWriteTimeUtc(path) < since.UtcDateTime) continue;

            StreamReader reader;
            try
            {
                Stream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)) stream = new GZipStream(stream, CompressionMode.Decompress);
                reader = new StreamReader(stream);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                logger.LogWarning("Cannot read {Path}: {Error}", path, ex.Message);
                continue;
            }

            using (reader)
            {
                while (reader.ReadLine() is { } line) yield return line;
            }
        }
    }

    // The defaults of LogFileOptions and the bound configuration end up in the same list (binding appends):
    // a file listed twice would be read twice, and every attempt counted twice.
    private static IEnumerable<string> Expand(IEnumerable<string> patterns) => ExpandAll(patterns).Distinct(StringComparer.Ordinal);

    private static IEnumerable<string> ExpandAll(IEnumerable<string> patterns)
    {
        foreach (var pattern in patterns.Distinct(StringComparer.Ordinal))
        {
            var dir = Path.GetDirectoryName(pattern);
            var name = Path.GetFileName(pattern);
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
            if (!name.Contains('*', StringComparison.Ordinal))
            {
                if (File.Exists(pattern)) yield return pattern;
                continue;
            }
            foreach (var file in Directory.EnumerateFiles(dir, name).Order(StringComparer.Ordinal)) yield return file;
        }
    }
}
