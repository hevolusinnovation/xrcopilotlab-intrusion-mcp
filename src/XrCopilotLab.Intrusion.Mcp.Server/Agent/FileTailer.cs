using System.Security.Cryptography;
using System.Text;

namespace XrCopilotLab.Intrusion.Mcp.Server.Agent;

/// <summary>How far a file was read, and the fingerprint of its first bytes: a rotated file starts with other bytes.</summary>
public sealed record TailCursor(long Offset, string Head);

public sealed record TailRead(IReadOnlyList<string> Lines, TailCursor? Cursor, bool Rotated, bool More);

/// <summary>
/// Reads what was appended to a log since the last round, whole lines only. A file is the same file as long as the
/// bytes already read are unchanged (they never change in an append-only log): if it is shorter, or starts differently,
/// it was rotated — the rest of the old one is read from <c>&lt;file&gt;.1</c>, then the new one from the start.
/// </summary>
public static class FileTailer
{
    public const int HeadBytes = 64;

    public static TailRead Read(string path, TailCursor? cursor, int maxBytes, long initialBackfill)
    {
        if (!File.Exists(path)) return new TailRead([], cursor, false, false);

        using var stream = Open(path);
        var length = stream.Length;
        var lines = new List<string>();
        var rotated = false;
        long start;

        if (cursor is null)
        {
            start = Math.Max(0, length - initialBackfill);
        }
        else if (length < cursor.Offset || Head(stream, Math.Min(cursor.Offset, HeadBytes)) != cursor.Head)
        {
            rotated = true;
            var previous = path + ".1";
            if (File.Exists(previous))
            {
                using var old = Open(previous);
                if (old.Length >= cursor.Offset && Head(old, Math.Min(cursor.Offset, HeadBytes)) == cursor.Head)
                    lines.AddRange(ReadLines(old, cursor.Offset, maxBytes, skipPartialFirst: false).Lines);
            }
            start = 0;
        }
        else
        {
            start = cursor.Offset;
        }

        var (read, end) = ReadLines(stream, start, maxBytes, skipPartialFirst: cursor is null && start > 0);
        lines.AddRange(read);
        return new TailRead(lines, new TailCursor(end, Head(stream, Math.Min(end, HeadBytes))), rotated, end < length && end - start >= maxBytes / 2);
    }

    private static FileStream Open(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

    /// <summary>The whole lines from <paramref name="start"/>, and the offset after the last newline.</summary>
    private static (List<string> Lines, long End) ReadLines(FileStream stream, long start, int maxBytes, bool skipPartialFirst)
    {
        stream.Seek(start, SeekOrigin.Begin);
        var buffer = new byte[(int)Math.Min(maxBytes, Math.Max(0, stream.Length - start))];
        var n = 0;
        while (n < buffer.Length)
        {
            var r = stream.Read(buffer, n, buffer.Length - n);
            if (r == 0) break;
            n += r;
        }

        var span = buffer.AsSpan(0, n);
        var last = span.LastIndexOf((byte)'\n');
        if (last < 0) return ([], start);

        var first = 0;
        if (skipPartialFirst)
        {
            // The backfill starts in the middle of a line: drop it.
            first = span.IndexOf((byte)'\n') + 1;
        }

        var text = Encoding.UTF8.GetString(span[first..(last + 1)]);
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => l.TrimEnd('\r')).ToList();
        return (lines, start + last + 1);
    }

    private static string Head(FileStream stream, long count)
    {
        if (count <= 0) return "";
        stream.Seek(0, SeekOrigin.Begin);
        var buffer = new byte[count];
        var n = 0;
        while (n < count)
        {
            var r = stream.Read(buffer, n, (int)count - n);
            if (r == 0) break;
            n += r;
        }
        return Convert.ToHexStringLower(SHA256.HashData(buffer.AsSpan(0, n)));
    }
}
