using System.Collections.Concurrent;
using XrCopilotLab.Intrusion.Mcp.Core.Collector;

namespace XrCopilotLab.Intrusion.Mcp.Server.Collector;

/// <summary>The store as a folder: the Docker lab and the tests. One collector process writes it.</summary>
public sealed class FileByteLogStore(string root) : IByteLogStore
{
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _locks = new(StringComparer.Ordinal);

    public async Task AppendAsync(string path, ReadOnlyMemory<byte> data, CancellationToken ct)
    {
        var full = Full(path);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        var gate = _locks.GetOrAdd(full, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(ct);
        try
        {
            await using var stream = new FileStream(full, FileMode.Append, FileAccess.Write, FileShare.Read);
            await stream.WriteAsync(data, ct);
        }
        finally
        {
            gate.Release();
        }
    }

    public Task<IReadOnlyList<StoredPart>> ListAsync(string prefix, CancellationToken ct)
    {
        var dir = Full(prefix);
        if (!Directory.Exists(dir)) return Task.FromResult<IReadOnlyList<StoredPart>>([]);
        IReadOnlyList<StoredPart> parts = Directory.EnumerateFiles(dir, "*" + StorePaths.Extension, SearchOption.AllDirectories)
            .Select(f => new StoredPart(Path.GetRelativePath(root, f).Replace('\\', '/'), new FileInfo(f).Length))
            .ToList();
        return Task.FromResult(parts);
    }

    public async Task<byte[]> ReadAsync(string path, long offset, long length, CancellationToken ct)
    {
        await using var stream = new FileStream(Full(path), FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        stream.Seek(offset, SeekOrigin.Begin);
        var buffer = new byte[length];
        var read = 0;
        while (read < length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(read), ct);
            if (n == 0) break;
            read += n;
        }
        return read == length ? buffer : buffer[..read];
    }

    public Task DeleteAsync(string path, CancellationToken ct)
    {
        File.Delete(Full(path));
        return Task.CompletedTask;
    }

    // Paths come from StorePaths (validated names), never from a caller: still, nothing may leave the root.
    private string Full(string path)
    {
        var full = Path.GetFullPath(Path.Combine(root, path));
        var rootFull = Path.GetFullPath(root);
        if (!full.StartsWith(rootFull, StringComparison.Ordinal)) throw new InvalidOperationException("path outside the store");
        return full;
    }
}
