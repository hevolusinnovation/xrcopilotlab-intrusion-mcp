using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Blobs.Specialized;
using XrCopilotLab.Intrusion.Mcp.Core.Collector;

namespace XrCopilotLab.Intrusion.Mcp.Server.Collector;

/// <summary>
/// The store on Azure: one append blob per file. Each block holds whole lines, so two replicas appending at the same
/// time interleave lines, never pieces of a line. Old days are deleted by the collector and by the account's lifecycle rule.
/// </summary>
public sealed class BlobByteLogStore(BlobContainerClient container) : IByteLogStore
{
    private readonly Lazy<Task> _created = new(() => container.CreateIfNotExistsAsync());

    public async Task AppendAsync(string path, ReadOnlyMemory<byte> data, CancellationToken ct)
    {
        await _created.Value;
        var blob = container.GetAppendBlobClient(path);
        await blob.CreateIfNotExistsAsync(cancellationToken: ct);
        var max = blob.AppendBlobMaxAppendBlockBytes;
        foreach (var block in Blocks(data, max))
        {
            using var stream = new MemoryStream(block.ToArray(), writable: false);
            await blob.AppendBlockAsync(stream, cancellationToken: ct);
        }
    }

    public async Task<IReadOnlyList<StoredPart>> ListAsync(string prefix, CancellationToken ct)
    {
        await _created.Value;
        var parts = new List<StoredPart>();
        await foreach (var item in container.GetBlobsAsync(BlobTraits.None, BlobStates.None, prefix, ct))
            parts.Add(new StoredPart(item.Name, item.Properties.ContentLength ?? 0));
        return parts;
    }

    public async Task<byte[]> ReadAsync(string path, long offset, long length, CancellationToken ct)
    {
        var result = await container.GetBlobClient(path).DownloadContentAsync(
            new BlobDownloadOptions { Range = new HttpRange(offset, length) }, ct);
        return result.Value.Content.ToArray();
    }

    public async Task DeleteAsync(string path, CancellationToken ct) =>
        await container.GetBlobClient(path).DeleteIfExistsAsync(cancellationToken: ct);

    /// <summary>Splits after a newline, so that no block ends in the middle of a line.</summary>
    internal static IEnumerable<ReadOnlyMemory<byte>> Blocks(ReadOnlyMemory<byte> data, int max)
    {
        while (data.Length > max)
        {
            var cut = data.Span[..max].LastIndexOf((byte)'\n');
            var take = cut < 0 ? max : cut + 1;
            yield return data[..take];
            data = data[take..];
        }
        if (!data.IsEmpty) yield return data;
    }
}
