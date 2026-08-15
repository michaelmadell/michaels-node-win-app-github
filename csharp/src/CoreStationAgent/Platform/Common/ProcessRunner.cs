using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace CoreStationAgent.Platform.Common;

/// <summary>
/// Runs a helper executable and captures stdout. Several metrics have no
/// managed API and are only available from a vendor tool such as nvidia-smi.
/// </summary>
public interface IProcessRunner
{
    /// <summary>
    /// Executes <paramref name="fileName"/> and returns trimmed stdout, or an
    /// empty string if it is missing, fails, or exceeds <paramref name="timeout"/>.
    /// Never throws — a missing optional tool is an expected outcome.
    /// </summary>
    Task<string> RunAsync(
        string fileName,
        IEnumerable<string> arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken);

    /// <summary>
    /// Synchronous counterpart of <see cref="RunAsync"/>, for the parts of
    /// <see cref="Core.ISystemInformation"/> that are synchronous by contract.
    /// </summary>
    string Run(string fileName, IEnumerable<string> arguments, TimeSpan timeout);
}

public sealed class ProcessRunner : IProcessRunner
{
    private readonly ILogger<ProcessRunner> _logger;

    public ProcessRunner(ILogger<ProcessRunner> logger) => _logger = logger;

    public string Run(string fileName, IEnumerable<string> arguments, TimeSpan timeout)
    {
        try
        {
            using var process = Process.Start(BuildStartInfo(fileName, arguments));
            if (process is null)
            {
                return string.Empty;
            }

            // Read stdout before waiting: a child that fills the pipe buffer
            // blocks forever if nobody is draining it.
            var stdout = process.StandardOutput.ReadToEnd();

            if (!process.WaitForExit((int)timeout.TotalMilliseconds))
            {
                TryKill(process, fileName);
                return string.Empty;
            }

            return process.ExitCode == 0 ? stdout.Trim() : string.Empty;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException
                                       or IOException)
        {
            _logger.LogDebug("Command {FileName} unavailable or failed: {Message}", fileName, ex.Message);
            return string.Empty;
        }
    }

    public async Task<string> RunAsync(
        string fileName,
        IEnumerable<string> arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        try
        {
            using var process = Process.Start(BuildStartInfo(fileName, arguments));
            if (process is null)
            {
                return string.Empty;
            }

            using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutSource.CancelAfter(timeout);

            var stdoutTask = process.StandardOutput.ReadToEndAsync(timeoutSource.Token);

            try
            {
                await process.WaitForExitAsync(timeoutSource.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                TryKill(process, fileName);
                return string.Empty;
            }

            var stdout = await stdoutTask.ConfigureAwait(false);
            return process.ExitCode == 0 ? stdout.Trim() : string.Empty;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException
                                       or IOException or OperationCanceledException)
        {
            // The overwhelmingly common case is that the tool is not installed.
            _logger.LogDebug("Command {FileName} unavailable or failed: {Message}", fileName, ex.Message);
            return string.Empty;
        }
    }

    private static ProcessStartInfo BuildStartInfo(string fileName, IEnumerable<string> arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        return startInfo;
    }

    private void TryKill(Process process, string fileName)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception
                                       or NotSupportedException)
        {
            _logger.LogDebug("Could not kill timed-out process {FileName}: {Message}", fileName, ex.Message);
        }
    }
}
