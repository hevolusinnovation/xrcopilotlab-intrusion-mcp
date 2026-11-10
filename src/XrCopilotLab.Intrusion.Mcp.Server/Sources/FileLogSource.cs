using System.IO.Compression;
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

    /// <summary>How many days back to read.</summary>
    public int MaxDays { get; set; } = 30;
}

/// <summary>
/// The real mode: reads the host's log files at every call, so nothing is kept and nothing is written. The account
/// the server runs as must be able to read them (on Ubuntu: group <c>adm</c>).
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
        Expand(options.Fail2banFiles).Concat(Expand(options.AuthFiles)).DefaultIfEmpty("no log file found: check Logs:Fail2banFiles and Logs:AuthFiles").ToList();

    public IReadOnlyList<LogEvent> Read(DateTimeOffset since, DateTimeOffset now)
    {
        var floor = now.AddDays(-options.MaxDays);
        if (since < floor) since = floor;

        var events = LogLines.Parse(Lines(options.Fail2banFiles, since), Lines(options.AuthFiles, since), _zone, now)
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

    private static IEnumerable<string> Expand(IEnumerable<string> patterns)
    {
        foreach (var pattern in patterns)
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
