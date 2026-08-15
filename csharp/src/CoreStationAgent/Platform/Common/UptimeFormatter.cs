using System.Globalization;

namespace CoreStationAgent.Platform.Common;

public static class UptimeFormatter
{
    /// <summary>
    /// Renders uptime as "0d 00h 00m 00s", the shape the BMC display parses.
    /// </summary>
    public static string Format(TimeSpan uptime)
    {
        if (uptime < TimeSpan.Zero)
        {
            uptime = TimeSpan.Zero;
        }

        return string.Format(
            CultureInfo.InvariantCulture,
            "{0}d {1:00}h {2:00}m {3:00}s",
            (long)uptime.TotalDays,
            uptime.Hours,
            uptime.Minutes,
            uptime.Seconds);
    }
}
