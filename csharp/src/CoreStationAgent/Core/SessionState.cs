namespace CoreStationAgent.Core;

/// <summary>
/// Session state codes as sent in "sessionState, N". The values come from
/// the Windows WTS_* notification constants in WinUser.h; the Linux provider
/// maps logind states onto the same numbers so the BMC sees one vocabulary.
/// </summary>
public static class SessionState
{
    public const string AppStarting = "0";
    public const string ConsoleConnect = "1";
    public const string ConsoleDisconnect = "2";
    public const string RemoteConnect = "3";
    public const string RemoteDisconnect = "4";
    public const string Logon = "5";
    public const string Logoff = "6";
    public const string Lock = "7";
    public const string Unlock = "8";
    public const string RemoteControl = "9";
    public const string Create = "10";
    public const string Terminate = "11";
}
