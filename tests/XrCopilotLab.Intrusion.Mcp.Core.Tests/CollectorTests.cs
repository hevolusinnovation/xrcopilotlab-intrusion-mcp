using XrCopilotLab.Intrusion.Mcp.Core.Collector;
using XrCopilotLab.Intrusion.Mcp.Core.Models;
using XrCopilotLab.Intrusion.Mcp.Core.Sources;
using XrCopilotLab.Intrusion.Mcp.Server.Collector;
using Xunit;

namespace XrCopilotLab.Intrusion.Mcp.Core.Tests;

public class CollectorTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 10, 9, 0, 0, TimeSpan.Zero);

    private const string Ban = "2026-11-10 03:12:46,004 fail2ban.actions        [812]: NOTICE  [sshd] Ban 203.0.113.7";
    private const string Unban = "2026-11-10 04:12:46,004 fail2ban.actions        [812]: NOTICE  [sshd] Unban 203.0.113.7";
    private const string FailedLogin = "2026-11-10T03:12:45.123456+01:00 bastion-01 sshd[2345]: Failed password for invalid user admin from 203.0.113.7 port 51234 ssh2";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "xrc-collector-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }

    private StoredEvents Stored(int retentionDays = 30) => new(new FileByteLogStore(_root), retentionDays);

    private static IngestRequest Request(params (string Log, string[] Lines)[] logs) =>
        new("test/1.0", "Europe/Rome", logs.Select(l => new IngestLog(l.Log, l.Lines)).ToList());

    [Fact]
    public void Every_log_the_host_reads_has_a_name_the_collector_knows()
    {
        Assert.Equal(8, LogNames.All.Count);
        Assert.True(LogLines.TryParse(LogNames.Fail2ban, Ban, TimeZoneInfo.Utc, Now, out var e));
        Assert.Equal(LogEventKind.Ban, e!.Kind);
        Assert.False(LogLines.TryParse("syslog", Ban, TimeZoneInfo.Utc, Now, out _));
        Assert.False(LogLines.TryParse(LogNames.Auth, Ban, TimeZoneInfo.Utc, Now, out _));
    }

    [Fact]
    public void A_request_is_refused_for_an_unknown_log_or_too_long_a_line()
    {
        Assert.Null(IngestRules.Validate(Request((LogNames.Fail2ban, [Ban]))));
        Assert.NotNull(IngestRules.Validate(null));
        Assert.NotNull(IngestRules.Validate(Request()));
        Assert.Contains("unknown log", IngestRules.Validate(Request(("syslog", [Ban]))));
        Assert.Contains("longer", IngestRules.Validate(Request((LogNames.Auth, [new string('x', IngestRules.MaxLineLength + 1)]))));
    }

    [Fact]
    public void An_unknown_time_zone_falls_back_to_utc()
    {
        Assert.Equal(TimeZoneInfo.Utc, IngestRules.Zone(null));
        Assert.Equal(TimeZoneInfo.Utc, IngestRules.Zone("Nowhere/Land"));
        Assert.Equal("Europe/Rome", IngestRules.Zone("Europe/Rome").Id);
    }

    [Fact]
    public void Stored_lines_survive_a_damaged_line_and_wait_for_an_unfinished_one()
    {
        var good = StoredLineCodec.Encode([new StoredLine(Now, "UTC", Ban), new StoredLine(Now, "UTC", Unban)]);
        var data = good.Concat("not json\n"u8.ToArray()).Concat("{\"r\":\"2026"u8.ToArray()).ToArray();

        var (lines, consumed) = StoredLineCodec.Decode(data);

        Assert.Equal([Ban, Unban], lines.Select(l => l.Line));
        Assert.Equal(good.Length + "not json\n".Length, consumed);
    }

    [Theory]
    [InlineData("acme", true)]
    [InlineData("web-01.acme", true)]
    [InlineData("Acme", false)]
    [InlineData("../etc", false)]
    [InlineData("a/b", false)]
    [InlineData("", false)]
    public void Tenant_and_host_names_are_safe_path_segments(string name, bool valid) => Assert.Equal(valid, StorePaths.IsValidName(name));

    [Fact]
    public void A_path_says_its_day_and_its_log()
    {
        var path = StorePaths.For("acme", "web-01", new DateOnly(2026, 11, 10), LogNames.Auth);
        Assert.Equal("acme/web-01/2026-11-10/auth.jsonl", path);
        Assert.True(StorePaths.TryParse(path, out var day, out var log));
        Assert.Equal(new DateOnly(2026, 11, 10), day);
        Assert.Equal(LogNames.Auth, log);
        Assert.False(StorePaths.TryParse("acme/web-01/2026-11-10/syslog.jsonl", out _, out _));
    }

    [Fact]
    public async Task Only_the_lines_about_an_attack_are_stored_and_they_come_back_as_the_hosts_events()
    {
        var stored = Stored();
        var result = await stored.IngestAsync("acme", "web-01",
            Request((LogNames.Fail2ban, [Ban, "2026-11-10 03:00:00,000 fail2ban.server [812]: INFO Starting"]), (LogNames.Auth, [FailedLogin])), Now, default);

        Assert.Equal(3, result.Received);
        Assert.Equal(2, result.Stored);

        var (events, last) = await stored.LoadAsync("acme", "web-01", Now.AddMinutes(1), default);
        Assert.Equal(Now, last);
        Assert.Equal(2, events.Count);
        Assert.All(events, e => Assert.Equal("web-01", e.Host));
        Assert.All(events, e => Assert.Equal("203.0.113.7", e.SourceIp));
        // fail2ban writes local time: the zone the agent sent gives it its offset.
        Assert.Equal(TimeSpan.FromHours(1), events.Single(e => e.Kind == LogEventKind.Ban).Time.Offset);
    }

    [Fact]
    public async Task A_second_read_takes_only_what_arrived_since_and_a_host_never_sees_another()
    {
        var stored = Stored();
        await stored.IngestAsync("acme", "web-01", Request((LogNames.Fail2ban, [Ban])), Now, default);
        Assert.Single((await stored.LoadAsync("acme", "web-01", Now, default)).Events);

        await stored.IngestAsync("acme", "web-01", Request((LogNames.Fail2ban, [Unban])), Now.AddMinutes(5), default);
        await stored.IngestAsync("acme", "web-02", Request((LogNames.Auth, [FailedLogin])), Now.AddMinutes(5), default);
        await stored.IngestAsync("other", "web-01", Request((LogNames.Auth, [FailedLogin])), Now.AddMinutes(5), default);

        var (events, last) = await stored.LoadAsync("acme", "web-01", Now.AddMinutes(6), default);
        Assert.Equal([LogEventKind.Ban, LogEventKind.Unban], events.Select(e => e.Kind));
        Assert.Equal(Now.AddMinutes(5), last);
        Assert.Single((await stored.LoadAsync("other", "web-01", Now.AddMinutes(6), default)).Events);
        Assert.Empty((await stored.LoadAsync("acme", "web-03", Now.AddMinutes(6), default)).Events);
    }

    [Fact]
    public async Task Days_past_the_retention_are_deleted()
    {
        var stored = Stored(retentionDays: 7);
        await stored.IngestAsync("acme", "web-01", Request((LogNames.Fail2ban, [Ban])), Now.AddDays(-20), default);
        await stored.IngestAsync("acme", "web-01", Request((LogNames.Fail2ban, [Unban])), Now, default);

        Assert.Equal(1, await stored.PurgeAsync(Now, default));
        Assert.Equal(0, await stored.PurgeAsync(Now, default));
        Assert.Single((await stored.LoadAsync("acme", "web-01", Now, default)).Events);
    }

    [Fact]
    public void A_host_registered_with_a_name_that_is_no_path_segment_stops_the_collector()
    {
        var options = new CollectorOptions { Hosts = [new HostRegistration { Name = "web-01", Tenant = "acme", IngestKeyHash = "ab" }] };
        options.Validate();

        options.Hosts.Add(new HostRegistration { Name = "../web-02", Tenant = "acme", IngestKeyHash = "cd" });
        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    [Fact]
    public async Task The_file_store_does_not_leave_its_folder()
    {
        var store = new FileByteLogStore(_root);
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.AppendAsync("../outside.jsonl", new byte[] { 1 }, default));
    }

    [Fact]
    public void Hosts_seen_as_one_keep_their_names_and_their_own_bans()
    {
        var one = Host("web-01", Event(LogEventKind.Ban, Now.AddHours(-2), "web-01"), Event(LogEventKind.Unban, Now.AddHours(-1), "web-01"));
        var two = Host("web-02", Event(LogEventKind.Ban, Now.AddMinutes(-90), "web-02"));
        var merged = new MergedLogSource([one, two]);

        Assert.Equal("web-01, web-02", merged.Hostname);
        Assert.False(merged.Simulated);
        Assert.Equal(["web-01", "web-02"], merged.Hosts.Select(h => h.Name));
        var events = merged.Read(Now.AddDays(-1), Now);
        Assert.Equal(["web-01", "web-02", "web-01"], events.Select(e => e.Host));

        // The unban on web-01 does not lift the ban on web-02.
        Assert.Single(Analysis.ThreatAnalyzer.CurrentBans(events));
    }

    [Fact]
    public void A_list_of_events_answers_only_the_period_asked()
    {
        var source = Host("web-01", Event(LogEventKind.Ban, Now.AddHours(-30), "web-01"), Event(LogEventKind.Ban, Now.AddHours(-2), "web-01"),
            Event(LogEventKind.Ban, Now.AddHours(1), "web-01"));

        Assert.Equal(Now.AddHours(-2), Assert.Single(source.Read(Now.AddDays(-1), Now)).Time);
        Assert.Empty(source.Read(Now.AddMinutes(-10), Now));
    }

    private static EventListSource Host(string name, params LogEvent[] events) =>
        new(new HostInfo(name, false, Now), 30, [$"{name}: agent"], events.OrderBy(e => e.Time).ToList());

    private static LogEvent Event(LogEventKind kind, DateTimeOffset time, string host) =>
        new(time, kind, LogOrigin.Fail2ban, "203.0.113.7", "sshd") { Host = host };
}
