using Xunit;
using Microsoft.Extensions.Logging.Abstractions;
using XrCopilotLab.Intrusion.Mcp.Server.Sources;

namespace XrCopilotLab.Intrusion.Mcp.Core.Tests;

public class FileLogSourceTests
{
    [Fact]
    public void A_file_listed_twice_is_read_once()
    {
        // Configuration binding appends to the defaults of LogFileOptions: the same path ends up in the list twice.
        var dir = Directory.CreateTempSubdirectory().FullName;
        var auth = Path.Combine(dir, "auth.log");
        File.WriteAllLines(auth,
        [
            "2026-11-11T10:00:01.000000+01:00 lab-01 sshd[100]: Failed password for root from 203.0.113.20 port 40000 ssh2",
            "2026-11-11T10:00:02.000000+01:00 lab-01 sshd[100]: Failed password for root from 203.0.113.20 port 40001 ssh2",
        ]);
        var options = new LogFileOptions
        {
            TimeZone = "Europe/Rome",
            Fail2banFiles = [], FirewallFiles = [], WebAccessFiles = [], CrowdsecFiles = [],
            AuthFiles = [auth + "*", auth + "*", auth],
        };

        var events = new FileLogSource(options, NullLogger<FileLogSource>.Instance)
            .Read(DateTimeOffset.Parse("2026-11-11T08:00:00Z"), DateTimeOffset.Parse("2026-11-11T10:00:00Z"));

        Assert.Equal(2, events.Count);
        Directory.Delete(dir, true);
    }
}
