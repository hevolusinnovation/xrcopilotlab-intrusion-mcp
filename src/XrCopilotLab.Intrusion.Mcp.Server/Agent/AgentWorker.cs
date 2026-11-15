using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Options;
using XrCopilotLab.Intrusion.Mcp.Core.Collector;
using XrCopilotLab.Intrusion.Mcp.Core.Sources;
using XrCopilotLab.Intrusion.Mcp.Server.Authentication;

namespace XrCopilotLab.Intrusion.Mcp.Server.Agent;

/// <summary>
/// The agent: every few seconds reads what the logs gained, keeps the lines about a source address (the same parsers
/// as the collector, so ordinary traffic never leaves the host), and sends them to the collector. A round that fails
/// to send is repeated from the same point; nothing moves forward until the collector has the lines.
/// </summary>
public sealed class AgentWorker(IOptions<AgentOptions> options, IHttpClientFactory http, TimeProvider clock, ILogger<AgentWorker> logger) : BackgroundService
{
    public const string ClientName = "collector";
    public static readonly string Version = typeof(AgentWorker).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var o = options.Value;
        var zone = string.IsNullOrWhiteSpace(o.TimeZone) ? TimeZoneInfo.Local : TimeZoneInfo.FindSystemTimeZoneById(o.TimeZone);
        var state = LoadState(o.StateFile);
        var failures = 0;
        logger.LogInformation("Agent {Version}: sending {Logs} to {Collector}, zone {Zone}", Version,
            string.Join(", ", o.Files.Where(f => !string.IsNullOrWhiteSpace(f.Value)).Select(f => $"{f.Key}={f.Value}")), o.CollectorUrl, zone.Id);

        while (!stoppingToken.IsCancellationRequested)
        {
            var more = false;
            try
            {
                var (request, cursors, pending) = Round(o, zone, state);
                more = pending;
                if (request.Logs!.Count > 0)
                {
                    var client = http.CreateClient(ClientName);
                    using var response = await client.PostAsJsonAsync("ingest", request, stoppingToken);
                    if (!response.IsSuccessStatusCode)
                        throw new HttpRequestException($"collector answered {(int)response.StatusCode}");
                    logger.LogInformation("Sent {Lines} lines", request.Logs.Sum(l => l.Lines.Count));
                }
                foreach (var (log, cursor) in cursors) state[log] = cursor;
                SaveState(o.StateFile, state);
                failures = 0;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                failures++;
                more = false;
                logger.LogWarning("Round failed ({Failures} in a row), retrying from the same point: {Error}", failures, ex.Message);
            }

            if (more) continue;
            var delay = TimeSpan.FromSeconds(Math.Min(o.IntervalSeconds * Math.Pow(2, Math.Min(failures, 5)), 300));
            await Task.Delay(delay, clock, stoppingToken);
        }
    }

    /// <summary>One round: what each log gained, filtered. The cursors are committed only after the send.</summary>
    internal (IngestRequest Request, Dictionary<string, TailCursor> Cursors, bool More) Round(AgentOptions o, TimeZoneInfo zone, Dictionary<string, TailCursor> state)
    {
        var now = clock.GetUtcNow();
        var logs = new List<IngestLog>();
        var cursors = new Dictionary<string, TailCursor>(StringComparer.Ordinal);
        var more = false;
        var budget = IngestRules.MaxLines;
        foreach (var (log, path) in o.Files)
        {
            if (string.IsNullOrWhiteSpace(path) || budget <= 0) continue;
            var read = FileTailer.Read(path, state.GetValueOrDefault(log), o.MaxBytesPerRead, o.InitialBackfillBytes);
            if (read.Rotated) logger.LogInformation("{Path} rotated", path);
            if (read.Cursor is not null) cursors[log] = read.Cursor;
            more |= read.More;

            var keep = read.Lines
                .Where(l => l.Length <= IngestRules.MaxLineLength && LogLines.TryParse(log, l, zone, now, out _))
                .Take(budget)
                .ToList();
            budget -= keep.Count;
            if (keep.Count > 0) logs.Add(new IngestLog(log, keep));
        }
        return (new IngestRequest($"xrcopilotlab-intrusion-agent/{Version}", zone.Id, logs), cursors, more);
    }

    private Dictionary<string, TailCursor> LoadState(string file)
    {
        try
        {
            if (File.Exists(file))
                return JsonSerializer.Deserialize<Dictionary<string, TailCursor>>(File.ReadAllText(file)) ?? new();
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            logger.LogWarning("State {File} unreadable, starting over: {Error}", file, ex.Message);
        }
        return new Dictionary<string, TailCursor>(StringComparer.Ordinal);
    }

    private static void SaveState(string file, Dictionary<string, TailCursor> state)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        var tmp = file + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(state));
        File.Move(tmp, file, overwrite: true);
    }

    /// <summary>The HTTP client to the collector: its address, the agent key in the header, a timeout.</summary>
    public static void Configure(HttpClient client, AgentOptions o)
    {
        client.BaseAddress = new Uri(o.CollectorUrl.EndsWith('/') ? o.CollectorUrl : o.CollectorUrl + "/");
        client.DefaultRequestHeaders.Add(ApiKeyOptions.HeaderName, o.Key);
        client.Timeout = TimeSpan.FromSeconds(60);
    }
}
