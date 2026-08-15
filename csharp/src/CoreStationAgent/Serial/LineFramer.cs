using System.Text;

namespace CoreStationAgent.Serial;

/// <summary>
/// Reassembles the byte stream into CR/LF-delimited lines. Serial reads split
/// wherever the driver happens to return, so a line routinely arrives across
/// several reads and several lines can arrive in one.
/// </summary>
public sealed class LineFramer
{
    private const int MaxBufferedChars = 64 * 1024;

    private static readonly char[] LineTerminators = ['\r', '\n'];

    private readonly StringBuilder _buffer = new();

    /// <summary>
    /// Adds a chunk and returns the lines it completed. Blank lines are
    /// dropped, so a CRLF pair yields one line rather than an empty extra.
    /// </summary>
    public IReadOnlyList<string> Append(string chunk)
    {
        if (string.IsNullOrEmpty(chunk))
        {
            return Array.Empty<string>();
        }

        _buffer.Append(chunk);

        // A peer that never sends a terminator would otherwise grow this
        // without bound; discard the backlog rather than the newest data.
        if (_buffer.Length > MaxBufferedChars)
        {
            _buffer.Clear();
            return Array.Empty<string>();
        }

        var text = _buffer.ToString();
        var lastBreak = text.LastIndexOfAny(LineTerminators);
        if (lastBreak < 0)
        {
            return Array.Empty<string>();
        }

        // Everything after the final terminator is an incomplete line; keep it
        // buffered for the next read.
        _buffer.Clear();
        _buffer.Append(text[(lastBreak + 1)..]);

        var lines = new List<string>();
        foreach (var line in text[..(lastBreak + 1)].Split(LineTerminators, StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();
            if (trimmed.Length > 0)
            {
                lines.Add(trimmed);
            }
        }

        return lines;
    }

    public void Reset() => _buffer.Clear();
}
