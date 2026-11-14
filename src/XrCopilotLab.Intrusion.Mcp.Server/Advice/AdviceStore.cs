using System.Text.Json;
using XrCopilotLab.Intrusion.Mcp.Core.Advice;

namespace XrCopilotLab.Intrusion.Mcp.Server.Advice;

/// <summary><c>Advice:Path</c> (a JSON file) and <c>Advice:MaxItems</c>. With no path the store uses the systemd
/// <c>StateDirectory</c> (<c>/var/lib/xrcopilotlab-intrusion-mcp</c>), or a temp folder when there is none.</summary>
public sealed class AdviceOptions
{
    public const string SectionName = "Advice";
    public string? Path { get; set; }
    public int MaxItems { get; set; } = AdviceLimits.DefaultMaxItems;
}

/// <summary>
/// Keeps the approved advice in an <see cref="AdviceLedger"/> and persists it to a small JSON file so it survives a
/// restart. If the file cannot be prepared (a read-only or scaled-to-zero host), it runs in memory and says so once:
/// the toolkit still never fails a request over this. It only stores and shows advice; it never applies any of it.
/// </summary>
public sealed class AdviceStore
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly AdviceLedger _ledger;
    private readonly ILogger<AdviceStore> _log;
    private readonly object _io = new();
    private readonly string? _path;

    public AdviceStore(AdviceOptions options, ILogger<AdviceStore> log)
    {
        _log = log;
        _ledger = new AdviceLedger(options.MaxItems);
        _path = ResolvePath(options.Path);
        Load();
    }

    public (AdviceItem Item, bool Created) Upsert(AdviceRequest request, DateTimeOffset now)
    {
        var result = _ledger.Upsert(request, now);
        Save();
        return result;
    }

    public IReadOnlyList<AdviceItem> List(DateTimeOffset now, int? hours) => _ledger.List(now, hours);

    public bool MarkDone(string id, DateTimeOffset now)
    {
        var ok = _ledger.MarkDone(id, now);
        if (ok) Save();
        return ok;
    }

    private void Load()
    {
        if (_path is null || !File.Exists(_path)) return;
        try
        {
            var items = JsonSerializer.Deserialize<List<AdviceItem>>(File.ReadAllText(_path), Json);
            if (items is not null) _ledger.LoadFrom(items);
        }
        catch (Exception ex)
        {
            _log.LogWarning("Cannot read the advice file {Path}: {Error}", _path, ex.Message);
        }
    }

    private void Save()
    {
        if (_path is null) return;
        try
        {
            lock (_io)
            {
                var tmp = _path + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(_ledger.Snapshot(), Json));
                File.Move(tmp, _path, overwrite: true);
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning("Cannot save the advice file {Path}: {Error}", _path, ex.Message);
        }
    }

    private string? ResolvePath(string? configured)
    {
        try
        {
            if (!string.IsNullOrWhiteSpace(configured))
            {
                var full = Path.GetFullPath(configured);
                Directory.CreateDirectory(Path.GetDirectoryName(full)!);
                return full;
            }

            // systemd StateDirectory= (a ':'-separated list on Linux); otherwise a temp folder for dev and tests.
            var state = Environment.GetEnvironmentVariable("STATE_DIRECTORY");
            var dir = !string.IsNullOrWhiteSpace(state)
                ? state.Split(Path.PathSeparator)[0]
                : Path.Combine(Path.GetTempPath(), "xrcopilotlab-intrusion-mcp");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "advice.json");
        }
        catch (Exception ex)
        {
            _log.LogWarning("Approved advice will not persist (cannot prepare a state directory): {Error}", ex.Message);
            return null;
        }
    }
}
