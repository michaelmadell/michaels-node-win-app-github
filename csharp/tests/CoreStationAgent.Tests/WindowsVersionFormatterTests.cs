using CoreStationAgent.Platform.Windows;
using Xunit;

namespace CoreStationAgent.Tests;

public class WindowsVersionFormatterTests
{
    [Fact]
    public void Windows11_IsCorrectedFromTheProductNameWindowsStillReports()
    {
        // Windows 11 reports "Windows 10 ..." in the registry, so the build
        // number is the only thing that distinguishes it.
        var result = WindowsVersionFormatter.Format("Windows 10 Pro", "24H2", 26100, "fallback");

        Assert.Equal("Windows 11 Pro 24H2", result);
    }

    [Fact]
    public void Windows10_IsLeftAlone()
    {
        var result = WindowsVersionFormatter.Format("Windows 10 Pro", "22H2", 19045, "fallback");

        Assert.Equal("Windows 10 Pro 22H2", result);
    }

    [Fact]
    public void Build22000_IsTheFirstBuildTreatedAsWindows11()
    {
        Assert.Equal("Windows 11 Pro", WindowsVersionFormatter.CorrectForWindows11("Windows 10 Pro", 22000));
        Assert.Equal("Windows 10 Pro", WindowsVersionFormatter.CorrectForWindows11("Windows 10 Pro", 21999));
    }

    [Fact]
    public void OnlyTheFirstTenIsRewritten()
    {
        // The edition year must survive the correction.
        var result = WindowsVersionFormatter.CorrectForWindows11("Windows 10 Enterprise LTSC 2021", 26100);

        Assert.Equal("Windows 11 Enterprise LTSC 2021", result);
    }

    [Fact]
    public void ProductNameWithoutATen_IsUnchanged()
    {
        var result = WindowsVersionFormatter.CorrectForWindows11("Windows Server 2025 Datacenter", 26100);

        Assert.Equal("Windows Server 2025 Datacenter", result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void MissingDisplayVersion_LeavesJustTheProductName(string? displayVersion)
    {
        var result = WindowsVersionFormatter.Format("Windows 10 Pro", displayVersion, 26100, "fallback");

        Assert.Equal("Windows 11 Pro", result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void MissingProductName_FallsBackToTheNumericVersion(string? productName)
    {
        var result = WindowsVersionFormatter.Format(productName, "24H2", 26100, "10.0.26100");

        Assert.Equal("10.0.26100", result);
    }

    [Fact]
    public void SurroundingWhitespace_IsTrimmed()
    {
        // Registry strings can carry a trailing NUL or padding.
        var result = WindowsVersionFormatter.Format("  Windows 10 Pro  ", "  24H2  ", 26100, "fallback");

        Assert.Equal("Windows 11 Pro 24H2", result);
    }
}
