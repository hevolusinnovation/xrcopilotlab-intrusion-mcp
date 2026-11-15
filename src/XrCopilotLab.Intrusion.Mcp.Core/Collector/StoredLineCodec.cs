using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace XrCopilotLab.Intrusion.Mcp.Core.Collector;

/// <summary>A log line as the collector stores it: when it arrived, the time zone of its host, the line itself.</summary>
public sealed record StoredLine(
    [property: JsonPropertyName("r")] DateTimeOffset Received,
    [property: JsonPropertyName("z")] string Zone,
    [property: JsonPropertyName("l")] string Line);

/// <summary>JSON lines in, JSON lines out. A trailing line without its newline is left for the next read.</summary>
public static class StoredLineCodec
{
    public static byte[] Encode(IEnumerable<StoredLine> lines)
    {
        var sb = new StringBuilder();
        foreach (var line in lines) sb.Append(JsonSerializer.Serialize(line)).Append('\n');
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    /// <summary>The complete lines in <paramref name="data"/>, and how many bytes they take.</summary>
    public static (IReadOnlyList<StoredLine> Lines, int Consumed) Decode(ReadOnlySpan<byte> data)
    {
        var lines = new List<StoredLine>();
        var consumed = 0;
        while (consumed < data.Length)
        {
            var end = data[consumed..].IndexOf((byte)'\n');
            if (end < 0) break;
            var raw = data.Slice(consumed, end);
            consumed += end + 1;
            if (raw.IsEmpty) continue;
            try
            {
                if (JsonSerializer.Deserialize<StoredLine>(raw) is { } line) lines.Add(line);
            }
            catch (JsonException)
            {
                // A damaged line is skipped: the others in the file are still good.
            }
        }
        return (lines, consumed);
    }
}
