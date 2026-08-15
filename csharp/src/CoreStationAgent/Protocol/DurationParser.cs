using System.Globalization;

namespace CoreStationAgent.Protocol;

/// <summary>
/// Parsing for the two deadline forms a C2A shutdown/restart accepts.
/// </summary>
public static class DurationParser
{
    /// <summary>
    /// Parses a relative duration: digits followed by exactly one unit
    /// character, e.g. "30s", "5m", "1h". Zero and negative values are
    /// rejected so a malformed command cannot become an instant shutdown.
    /// </summary>
    public static bool TryParseDuration(string? text, out TimeSpan duration)
    {
        duration = default;

        if (string.IsNullOrWhiteSpace(text) || text.Length < 2)
        {
            return false;
        }

        text = text.Trim();

        var digits = text[..^1];
        var unit = char.ToLowerInvariant(text[^1]);

        if (!long.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out var value) || value <= 0)
        {
            return false;
        }

        try
        {
            duration = unit switch
            {
                's' => TimeSpan.FromSeconds(value),
                'm' => TimeSpan.FromMinutes(value),
                'h' => TimeSpan.FromHours(value),
                _ => TimeSpan.Zero,
            };
        }
        catch (OverflowException)
        {
            return false;
        }

        return duration > TimeSpan.Zero;
    }

    /// <summary>
    /// Parses an absolute local wall-clock deadline, "yyyy-MM-dd HH:mm:ss".
    /// </summary>
    public static bool TryParseLocalDateTime(string? text, out DateTimeOffset deadline)
    {
        deadline = default;

        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        if (!DateTime.TryParseExact(
                text.Trim(),
                "yyyy-MM-dd HH:mm:ss",
                CultureInfo.InvariantCulture,
                DateTimeStyles.None,
                out var parsed))
        {
            return false;
        }

        deadline = new DateTimeOffset(DateTime.SpecifyKind(parsed, DateTimeKind.Local));
        return true;
    }

    /// <summary>Formats a deadline the way the BMC expects to read it back.</summary>
    public static string Format(DateTimeOffset value) =>
        value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
}
