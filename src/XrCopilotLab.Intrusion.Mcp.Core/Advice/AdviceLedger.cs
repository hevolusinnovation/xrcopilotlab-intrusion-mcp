namespace XrCopilotLab.Intrusion.Mcp.Core.Advice;

/// <summary>
/// The in-memory ledger of approved advice: validate a request, add it or update the one with the same id (never a
/// duplicate), keep at most the newest N, list them newest first, mark one done. No I/O — a store in the server layer
/// loads it from a file and saves it after each change. Thread-safe.
/// </summary>
public sealed class AdviceLedger
{
    private readonly object _gate = new();
    private readonly List<AdviceItem> _items = []; // oldest first
    private readonly int _max;

    public AdviceLedger(int maxItems = AdviceLimits.DefaultMaxItems) =>
        _max = maxItems > 0 ? maxItems : AdviceLimits.DefaultMaxItems;

    /// <summary>Replace the contents (used once at load). Keeps only the newest <c>maxItems</c>.</summary>
    public void LoadFrom(IEnumerable<AdviceItem> items)
    {
        lock (_gate)
        {
            _items.Clear();
            foreach (var i in items) _items.Add(i);
            Trim();
        }
    }

    /// <summary>Add the advice, or update the one with the same id. <c>Created</c> is false on an update (keeps the
    /// original <c>ReceivedAt</c> and <c>Status</c>). Throws <see cref="AdviceValidationException"/> on a bad body.</summary>
    public (AdviceItem Item, bool Created) Upsert(AdviceRequest request, DateTimeOffset now)
    {
        var v = Validate(request);
        lock (_gate)
        {
            var idx = _items.FindIndex(x => x.Id == v.Id);
            if (idx >= 0)
            {
                var updated = _items[idx] with
                {
                    FindingId = v.FindingId,
                    Ip = v.Ip,
                    Severity = v.Severity,
                    Title = v.Title,
                    Recommendation = v.Recommendation,
                    Command = v.Command,
                    ApprovedBy = v.ApprovedBy,
                    ApprovedAt = v.ApprovedAt,
                    Source = v.Source,
                };
                _items[idx] = updated;
                return (updated, false);
            }

            var item = new AdviceItem(v.Id, v.FindingId, v.Ip, v.Severity, v.Title, v.Recommendation, v.Command,
                v.ApprovedBy, v.ApprovedAt, v.Source, now, AdviceLimits.StatusReceived, null);
            _items.Add(item);
            Trim();
            return (item, true);
        }
    }

    /// <summary>The advice newest first, optionally only that received in the last <paramref name="hours"/>.</summary>
    public IReadOnlyList<AdviceItem> List(DateTimeOffset now, int? hours)
    {
        lock (_gate)
        {
            IEnumerable<AdviceItem> q = _items;
            if (hours is int h && h > 0)
            {
                var since = now - TimeSpan.FromHours(h);
                q = q.Where(x => x.ReceivedAt >= since);
            }
            return q.Reverse().ToList();
        }
    }

    /// <summary>Mark one done. False if no advice has that id; true (idempotent) if it was already done.</summary>
    public bool MarkDone(string id, DateTimeOffset now)
    {
        var key = id?.Trim();
        if (string.IsNullOrEmpty(key)) return false;
        lock (_gate)
        {
            var idx = _items.FindIndex(x => x.Id == key);
            if (idx < 0) return false;
            if (_items[idx].Status != AdviceLimits.StatusDone)
                _items[idx] = _items[idx] with { Status = AdviceLimits.StatusDone, DoneAt = now };
            return true;
        }
    }

    /// <summary>A copy of everything kept, oldest first (for saving).</summary>
    public IReadOnlyList<AdviceItem> Snapshot()
    {
        lock (_gate) return _items.ToList();
    }

    private void Trim()
    {
        while (_items.Count > _max) _items.RemoveAt(0);
    }

    // Normalizes and checks a request; builds the canonical fields. Collects every problem into one message.
    private static AdviceItem Validate(AdviceRequest r)
    {
        var errors = new List<string>();

        var id = Required(r.Id, "id", AdviceLimits.MaxId, errors);
        var title = Required(r.Title, "title", AdviceLimits.MaxTitle, errors);
        var recommendation = Required(r.Recommendation, "recommendation", AdviceLimits.MaxRecommendation, errors);
        var approvedBy = Required(r.ApprovedBy, "approvedBy", AdviceLimits.MaxField, errors);

        var severity = Canon(r.Severity);
        if (severity is null) errors.Add($"severity must be one of {string.Join(", ", AdviceLimits.Severities)}");

        if (r.ApprovedAt is null) errors.Add("approvedAt is required (ISO-8601)");

        var findingId = Optional(r.FindingId, "findingId", AdviceLimits.MaxField, errors);
        var ip = Optional(r.Ip, "ip", AdviceLimits.MaxIp, errors);
        var command = Optional(r.Command, "command", AdviceLimits.MaxCommand, errors);
        var source = string.IsNullOrWhiteSpace(r.Source) ? AdviceLimits.DefaultSource : Optional(r.Source, "source", AdviceLimits.MaxSource, errors) ?? AdviceLimits.DefaultSource;

        if (errors.Count > 0) throw new AdviceValidationException(string.Join("; ", errors));

        return new AdviceItem(id!, findingId, ip, severity!, title!, recommendation!, command,
            approvedBy!, r.ApprovedAt!.Value, source, default, AdviceLimits.StatusReceived, null);
    }

    private static string? Required(string? value, string name, int max, List<string> errors)
    {
        var v = value?.Trim();
        if (string.IsNullOrEmpty(v)) { errors.Add($"{name} is required"); return null; }
        if (v.Length > max) { errors.Add($"{name} is longer than {max} characters"); return v[..max]; }
        return v;
    }

    private static string? Optional(string? value, string name, int max, List<string> errors)
    {
        var v = value?.Trim();
        if (string.IsNullOrEmpty(v)) return null;
        if (v.Length > max) { errors.Add($"{name} is longer than {max} characters"); return v[..max]; }
        return v;
    }

    private static string? Canon(string? severity) => severity?.Trim().ToLowerInvariant() switch
    {
        "low" => "Low",
        "medium" => "Medium",
        "high" => "High",
        "critical" => "Critical",
        _ => null,
    };
}
