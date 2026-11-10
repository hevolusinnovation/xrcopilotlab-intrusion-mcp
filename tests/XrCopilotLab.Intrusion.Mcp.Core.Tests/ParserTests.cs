using XrCopilotLab.Intrusion.Mcp.Core.Models;
using XrCopilotLab.Intrusion.Mcp.Core.Parsing;
using Xunit;

namespace XrCopilotLab.Intrusion.Mcp.Core.Tests;

public class Fail2banLogParserTests
{
    private static readonly TimeZoneInfo Rome = TimeZoneInfo.FindSystemTimeZoneById("Europe/Rome");

    [Theory]
    [InlineData("2026-11-10 03:12:45,123 fail2ban.filter         [812]: INFO    [sshd] Found 203.0.113.7 - 2026-11-10 03:12:45", LogEventKind.Found)]
    [InlineData("2026-11-10 03:12:46,004 fail2ban.actions        [812]: NOTICE  [sshd] Ban 203.0.113.7", LogEventKind.Ban)]
    [InlineData("2026-11-10 03:12:46,004 fail2ban.actions        [812]: NOTICE  [sshd] Unban 203.0.113.7", LogEventKind.Unban)]
    [InlineData("2026-11-10 03:12:46,004 fail2ban.actions        [812]: NOTICE  [sshd] Restore Ban 203.0.113.7", LogEventKind.RestoreBan)]
    public void Reads_the_four_lines_about_an_address(string line, LogEventKind kind)
    {
        Assert.True(Fail2banLogParser.TryParse(line, Rome, out var e));
        Assert.Equal(kind, e!.Kind);
        Assert.Equal("sshd", e.Jail);
        Assert.Equal("203.0.113.7", e.SourceIp);
        Assert.Equal(LogOrigin.Fail2ban, e.Origin);
    }

    [Fact]
    public void Local_time_gets_the_offset_of_the_hosts_zone()
    {
        Assert.True(Fail2banLogParser.TryParse("2026-11-10 03:12:46,004 fail2ban.actions [812]: NOTICE [sshd] Ban 203.0.113.7", Rome, out var winter));
        Assert.Equal(TimeSpan.FromHours(1), winter!.Time.Offset);
        Assert.True(Fail2banLogParser.TryParse("2026-07-10 03:12:46,004 fail2ban.actions [812]: NOTICE [sshd] Ban 203.0.113.7", Rome, out var summer));
        Assert.Equal(TimeSpan.FromHours(2), summer!.Time.Offset);
    }

    [Fact]
    public void Reads_ipv6_and_any_jail_name()
    {
        Assert.True(Fail2banLogParser.TryParse("2026-11-10 03:12:46,004 fail2ban.actions [812]: NOTICE [nginx-botsearch] Ban 2001:db8::42", Rome, out var e));
        Assert.Equal("2001:db8::42", e!.SourceIp);
        Assert.Equal("nginx-botsearch", e.Jail);
    }

    [Theory]
    [InlineData("2026-11-10 03:12:46,004 fail2ban.actions [812]: NOTICE [sshd] 203.0.113.7 already banned")]
    [InlineData("2026-11-10 03:00:00,001 fail2ban.server  [812]: INFO    Starting Fail2ban v1.0.2")]
    [InlineData("2026-11-10 03:00:00,001 fail2ban.jail    [812]: INFO    Jail 'sshd' started")]
    [InlineData("")]
    public void Ignores_lines_that_are_not_about_an_address(string line) =>
        Assert.False(Fail2banLogParser.TryParse(line, Rome, out _));
}

public class AuthLogParserTests
{
    private static readonly TimeZoneInfo Rome = TimeZoneInfo.FindSystemTimeZoneById("Europe/Rome");
    private static readonly DateTimeOffset Now = new(2026, 11, 10, 12, 0, 0, TimeSpan.FromHours(1));

    [Fact]
    public void Failed_password_for_an_invalid_user()
    {
        const string line = "2026-11-10T03:12:45.123456+01:00 bastion-01 sshd[2345]: Failed password for invalid user admin from 203.0.113.7 port 51234 ssh2";
        Assert.True(AuthLogParser.TryParse(line, Rome, Now, out var e));
        Assert.Equal(LogEventKind.FailedLogin, e!.Kind);
        Assert.Equal("admin", e.User);
        Assert.Equal("203.0.113.7", e.SourceIp);
        Assert.Equal(51234, e.Port);
        Assert.Equal("password", e.Method);
        Assert.Equal(new DateTimeOffset(2026, 11, 10, 3, 12, 45, TimeSpan.FromHours(1)).AddTicks(1234560), e.Time);
    }

    [Fact]
    public void Failed_password_for_an_existing_user()
    {
        Assert.True(AuthLogParser.TryParse("2026-11-10T03:12:45+01:00 h sshd[1]: Failed password for root from 203.0.113.7 port 51234 ssh2", Rome, Now, out var e));
        Assert.Equal(("root", LogEventKind.FailedLogin), (e!.User, e.Kind));
    }

    [Fact]
    public void Invalid_user_line()
    {
        Assert.True(AuthLogParser.TryParse("2026-11-10T03:12:44+01:00 h sshd[1]: Invalid user scada from 192.0.2.8 port 40000", Rome, Now, out var e));
        Assert.Equal(("scada", LogEventKind.InvalidUser, "192.0.2.8"), (e!.User, e.Kind, e.SourceIp));
    }

    [Fact]
    public void Accepted_publickey_with_fingerprint_and_the_openssh_98_process_name()
    {
        const string line = "2026-11-10T08:05:00+01:00 h sshd-session[77]: Accepted publickey for deploy from 198.51.100.9 port 50122 ssh2: ED25519 SHA256:abc";
        Assert.True(AuthLogParser.TryParse(line, Rome, Now, out var e));
        Assert.Equal((LogEventKind.AcceptedLogin, "deploy", "publickey"), (e!.Kind, e.User, e.Method));
    }

    [Fact]
    public void Classic_syslog_format_takes_this_year_and_the_zone()
    {
        Assert.True(AuthLogParser.TryParse("Nov  9 03:12:45 h sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2", Rome, Now, out var e));
        Assert.Equal(new DateTimeOffset(2026, 11, 9, 3, 12, 45, TimeSpan.FromHours(1)), e!.Time);
    }

    [Fact]
    public void Classic_format_in_january_puts_a_december_line_in_last_year()
    {
        var january = new DateTimeOffset(2027, 1, 2, 10, 0, 0, TimeSpan.FromHours(1));
        Assert.True(AuthLogParser.TryParse("Dec 31 23:59:00 h sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2", Rome, january, out var e));
        Assert.Equal(2026, e!.Time.Year);
    }

    [Theory]
    [InlineData("2026-11-10T03:12:45+01:00 h sshd[1]: Connection closed by invalid user admin 203.0.113.7 port 51234 [preauth]")]
    [InlineData("2026-11-10T03:12:45+01:00 h sshd[1]: pam_unix(sshd:session): session opened for user deploy(uid=1001) by deploy(uid=0)")]
    [InlineData("2026-11-10T03:12:45+01:00 h CRON[1]: pam_unix(cron:session): session opened for user root")]
    public void Ignores_lines_that_are_not_a_login(string line) =>
        Assert.False(AuthLogParser.TryParse(line, Rome, Now, out _));
}
