namespace XrCopilotLab.Intrusion.Mcp.Core.Collector;

/// <summary>One append-only file of the store, with its current length.</summary>
public sealed record StoredPart(string Path, long Length);

/// <summary>
/// Where the collector keeps what the agents send: append-only files of JSON lines, one per tenant, host, day of
/// receipt and log (<see cref="StorePaths"/>). A folder on disk in the lab, append blobs on Azure.
/// </summary>
public interface IByteLogStore
{
    /// <summary>Appends whole lines at the end of the file, creating it if needed.</summary>
    Task AppendAsync(string path, ReadOnlyMemory<byte> data, CancellationToken ct);

    /// <summary>The files under a prefix (<c>tenant/host/</c>), with their length.</summary>
    Task<IReadOnlyList<StoredPart>> ListAsync(string prefix, CancellationToken ct);

    /// <summary>The bytes of a file from <paramref name="offset"/> for <paramref name="length"/> bytes.</summary>
    Task<byte[]> ReadAsync(string path, long offset, long length, CancellationToken ct);

    Task DeleteAsync(string path, CancellationToken ct);
}
