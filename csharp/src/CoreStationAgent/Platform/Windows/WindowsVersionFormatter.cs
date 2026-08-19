namespace CoreStationAgent.Platform.Windows;

/// <summary>
/// Composes the friendly Windows edition string from the raw registry values.
///
/// Deliberately free of Windows APIs — it is pure string handling, which keeps
/// the interesting part (the Windows 11 correction) testable on any host.
/// </summary>
public static class WindowsVersionFormatter
{
    /// <summary>
    /// Windows 11 still reports a ProductName of "Windows 10 ..." for
    /// application-compatibility reasons; the build number is the only
    /// reliable discriminator, and 22000 is the first Windows 11 build.
    /// </summary>
    public const int FirstWindows11Build = 22000;

    /// <summary>
    /// Builds the string sent as "winVersion", e.g. "Windows 11 Pro 24H2".
    /// </summary>
    /// <param name="productName">Registry ProductName, e.g. "Windows 10 Pro".</param>
    /// <param name="displayVersion">Registry DisplayVersion, e.g. "24H2". May be absent.</param>
    /// <param name="buildNumber">The real OS build number.</param>
    /// <param name="fallback">Used when ProductName is unavailable.</param>
    public static string Format(string? productName, string? displayVersion, int buildNumber, string fallback)
    {
        if (string.IsNullOrWhiteSpace(productName))
        {
            return fallback;
        }

        var name = CorrectForWindows11(productName.Trim(), buildNumber);

        return string.IsNullOrWhiteSpace(displayVersion)
            ? name
            : $"{name} {displayVersion.Trim()}";
    }

    /// <summary>
    /// Rewrites the "10" in the product name to "11" on Windows 11 builds.
    /// Only the first occurrence is replaced, so an edition that legitimately
    /// contains another number (for instance "Windows 10 Enterprise LTSC 2021")
    /// keeps it.
    /// </summary>
    public static string CorrectForWindows11(string productName, int buildNumber)
    {
        if (buildNumber < FirstWindows11Build)
        {
            return productName;
        }

        var position = productName.IndexOf("10", StringComparison.Ordinal);

        return position < 0
            ? productName
            : string.Concat(productName.AsSpan(0, position), "11", productName.AsSpan(position + 2));
    }
}
