using System.Collections.Concurrent;
using XrCopilotLab.Intrusion.Mcp.Core.Models;
using XrCopilotLab.Intrusion.Mcp.Core.Sources;

namespace XrCopilotLab.Intrusion.Mcp.Core.Collector;

/// <summary>
/// The collector's events: what agents send is written to the store, what a query needs is read back and parsed by the
/// same parsers as a host read in place. Files only grow, so each one is read once and then only from where the last
/// read stopped; a query lists the host's files (one call) and reads the new bytes, usually only today's.
/// </summary>
public sealed class StoredEvents(IByteLogStore store, int retentionDays)
{
    private readonly ConcurrentDictionary<string, HostCache> _hosts = new(StringComparer.Ordinal);
    private static readonly ConcurrentDictionary<string, TimeZoneInfo> Zones = new(StringComparer.Ordinal);

    public int RetentionDays => retentionDays;

    /// <summary>
    /// Stores the lines that say something about a source address; the others are dropped here, as the agent already
    /// does, so ordinary traffic (the visitors of a web site) is never kept.
    /// </summary>
    public async Task<IngestResult> IngestAsync(string tenant, string host, IngestRequest request, DateTimeOffset now, CancellationToken ct)
    {
        var zone = IngestRules.Zone(request.TimeZone);
        var day = DateOnly.FromDateTime(now.UtcDateTime);
        int received = 0, stored = 0;
        foreach (var log in request.Logs ?? [])
        {
            received += log.Lines.Count;
            var keep = log.Lines
                .Where(line => LogLines.TryParse(log.Log, line, zone, now, out _))
                .Select(line => new StoredLine(now, zone.Id, line))
                .ToList();
            if (keep.Count == 0) continue;
            await store.AppendAsync(StorePaths.For(tenant, host, day, log.Log), StoredLineCodec.Encode(keep), ct).ConfigureAwait(false);
            stored += keep.Count;
        }
        return new IngestResult(received, stored, now);
    }

    /// <summary>Every event of the host in the retention window, sorted, and when its agent last sent something.</summary>
    public async Task<(IReadOnlyList<LogEvent> Events, DateTimeOffset? LastReceived)> LoadAsync(string tenant, string host, DateTimeOffset now, CancellationToken ct)
    {
        var prefix = StorePaths.Prefix(tenant, host);
        var cache = _hosts.GetOrAdd(prefix, _ => new HostCache());
        await cache.Gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var floor = DateOnly.FromDateTime(now.UtcDateTime).AddDays(-retentionDays - 1);
            var listed = new HashSet<string>(StringComparer.Ordinal);
            foreach (var part in await store.ListAsync(prefix, ct).ConfigureAwait(false))
            {
                if (!StorePaths.TryParse(part.Path, out var day, out var log) || day < floor) continue;
                listed.Add(part.Path);
                var entry = cache.Parts.GetValueOrDefault(part.Path) ?? (cache.Parts[part.Path] = new PartCache(log));
                if (part.Length <= entry.Offset) continue;

                var bytes = await store.ReadAsync(part.Path, entry.Offset, part.Length - entry.Offset, ct).ConfigureAwait(false);
                var (lines, consumed) = StoredLineCodec.Decode(bytes);
                entry.Offset += consumed;
                foreach (var line in lines)
                {
                    if (entry.LastReceived is null || line.Received > entry.LastReceived) entry.LastReceived = line.Received;
                    if (LogLines.TryParse(entry.Log, line.Line, ZoneOf(line.Zone), line.Received, out var e))
                        entry.Events.Add(e! with { Host = host });
                }
            }

            foreach (var gone in cache.Parts.Keys.Where(k => !listed.Contains(k)).ToList()) cache.Parts.Remove(gone);

            var events = cache.Parts.Values.SelectMany(p => p.Events).ToList();
            events.Sort((a, b) => a.Time.CompareTo(b.Time));
            var last = cache.Parts.Values.Select(p => p.LastReceived).Where(t => t is not null).DefaultIfEmpty(null).Max();
            return (events, last);
        }
        finally
        {
            cache.Gate.Release();
        }
    }

    /// <summary>Deletes the files of the days past the retention, for every tenant and host. Returns how many.</summary>
    public async Task<int> PurgeAsync(DateTimeOffset now, CancellationToken ct)
    {
        var floor = DateOnly.FromDateTime(now.UtcDateTime).AddDays(-retentionDays - 1);
        var deleted = 0;
        foreach (var part in await store.ListAsync("", ct).ConfigureAwait(false))
        {
            if (!StorePaths.TryParse(part.Path, out var day, out _) || day >= floor) continue;
            await store.DeleteAsync(part.Path, ct).ConfigureAwait(false);
            deleted++;
        }
        return deleted;
    }

    private static TimeZoneInfo ZoneOf(string id) => Zones.GetOrAdd(id, IngestRules.Zone);

    private sealed class HostCache
    {
        public SemaphoreSlim Gate { get; } = new(1, 1);
        public Dictionary<string, PartCache> Parts { get; } = new(StringComparer.Ordinal);
    }

    private sealed class PartCache(string log)
    {
        public string Log { get; } = log;
        public long Offset { get; set; }
        public DateTimeOffset? LastReceived { get; set; }
        public List<LogEvent> Events { get; } = [];
    }
}
