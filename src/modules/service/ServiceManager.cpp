#ifdef _WIN32
#include "ServiceManager.h"
#include "../../platform/WindowsPlatform.h"
#include <iostream>
#include <sstream>

ServiceManager::ServiceManager(WindowsPlatform* platform)
    : platform_(platform) {

    // Initialize service status structure
    ZeroMemory(&serviceStatus_, sizeof(SERVICE_STATUS));
    serviceStatus_.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    serviceStatus_.dwCurrentState = SERVICE_STOPPED;
    serviceStatus_.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

    // Create stop event
    stopEvent_ = CreateEvent(NULL, TRUE, FALSE, NULL);
}

ServiceManager::~ServiceManager() {
    if (stopEvent_) {
        CloseHandle(stopEvent_);
        stopEvent_ = nullptr;
    }
}

bool ServiceManager::Install(const ServiceConfig& config) {
    SC_HANDLE scmHandle = nullptr;
    SC_HANDLE serviceHandle = nullptr;
    bool success = false;

    // Get the executable path
    wchar_t exePath[MAX_PATH];
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) {
        LogError("GetModuleFileName");
        return false;
    }

    // Open Service Control Manager
    scmHandle = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scmHandle) {
        LogError("OpenSCManager");
        return false;
    }

    // Create the service
    serviceHandle = CreateServiceW(
        scmHandle,
        config.serviceName.c_str(),
        config.displayName.c_str(),
        SERVICE_ALL_ACCESS,
        config.serviceType,
        config.startType,
        SERVICE_ERROR_NORMAL,
        exePath,
        NULL,
        NULL,
        config.dependencies.empty() ? NULL : config.dependencies.c_str(),
        config.account.c_str(),
        config.password.empty() ? NULL : config.password.c_str()
    );

    if (!serviceHandle) {
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            if (platform_) {
                platform_->logMessage("Service already exists");
            }
            success = true;
        }
        else {
            LogError("CreateService");
        }
    }
    else {
        // Set service description
        SERVICE_DESCRIPTIONW sd;
        std::wstring desc = config.description;
        sd.lpDescription = const_cast<LPWSTR>(desc.c_str());

        ChangeServiceConfig2W(serviceHandle, SERVICE_CONFIG_DESCRIPTION, &sd);

        if (platform_) {
            platform_->logMessage("Service installed successfully");
        }
        success = true;
    }

    if (serviceHandle) {
        CloseServiceHandle(serviceHandle);
    }
    if (scmHandle) {
        CloseServiceHandle(scmHandle);
    }

    return success;
}

bool ServiceManager::Uninstall() {
    SC_HANDLE scmHandle = nullptr;
    SC_HANDLE serviceHandle = nullptr;
    bool success = false;

    if (!OpenServiceManager(scmHandle)) {
        return false;
    }

    if (!OpenServiceHandle(scmHandle, serviceHandle, DELETE)) {
        CloseServiceHandle(scmHandle);
        return false;
    }

    // Stop the service if it's running
    SERVICE_STATUS status;
    if (ControlService(serviceHandle, SERVICE_CONTROL_STOP, &status)) {
        if (platform_) {
            platform_->logMessage("Stopping service...");
        }
        Sleep(1000);
    }

    // Delete the service
    if (DeleteService(serviceHandle)) {
        if (platform_) {
            platform_->logMessage("Service uninstalled successfully");
        }
        success = true;
    }
    else {
        LogError("DeleteService");
    }

    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);

    return success;
}

bool ServiceManager::StartService() {
    SC_HANDLE scmHandle = nullptr;
    SC_HANDLE serviceHandle = nullptr;
    bool success = false;

    if (!OpenServiceManager(scmHandle)) {
        return false;
    }

    if (!OpenServiceHandle(scmHandle, serviceHandle, SERVICE_START | SERVICE_QUERY_STATUS)) {
        CloseServiceHandle(scmHandle);
        return false;
    }

    // Check if already running
    SERVICE_STATUS status;
    if (QueryServiceStatus(serviceHandle, &status)) {
        if (status.dwCurrentState == SERVICE_RUNNING) {
            if (platform_) {
                platform_->logMessage("Service is already running");
            }
            success = true;
        }
    }

    if (!success) {
        if (::StartServiceW(serviceHandle, 0, NULL)) {
            if (platform_) {
                platform_->logMessage("Service start pending...");
            }

            // Wait for the service to start
            while (QueryServiceStatus(serviceHandle, &status)) {
                if (status.dwCurrentState == SERVICE_RUNNING) {
                    if (platform_) {
                        platform_->logMessage("Service started successfully");
                    }
                    success = true;
                    break;
                }

                if (status.dwCurrentState == SERVICE_STOPPED) {
                    LogError("Service failed to start");
                    break;
                }

                Sleep(100);
            }
        }
        else {
            LogError("StartService");
        }
    }

    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);

    return success;
}

bool ServiceManager::StopService() {
    SC_HANDLE scmHandle = nullptr;
    SC_HANDLE serviceHandle = nullptr;
    bool success = false;

    if (!OpenServiceManager(scmHandle)) {
        return false;
    }

    if (!OpenServiceHandle(scmHandle, serviceHandle, SERVICE_STOP | SERVICE_QUERY_STATUS)) {
        CloseServiceHandle(scmHandle);
        return false;
    }

    SERVICE_STATUS status;
    if (ControlService(serviceHandle, SERVICE_CONTROL_STOP, &status)) {
        if (platform_) {
            platform_->logMessage("Service stop pending...");
        }

        // Wait for the service to stop
        while (QueryServiceStatus(serviceHandle, &status)) {
            if (status.dwCurrentState == SERVICE_STOPPED) {
                if (platform_) {
                    platform_->logMessage("Service stopped successfully");
                }
                success = true;
                break;
            }
            Sleep(100);
        }
    }
    else {
        if (GetLastError() == ERROR_SERVICE_NOT_ACTIVE) {
            if (platform_) {
                platform_->logMessage("Service is not running");
            }
            success = true;
        }
        else {
            LogError("ControlService");
        }
    }

    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);

    return success;
}

bool ServiceManager::QueryStatus(ServiceStatus& status) {
    SC_HANDLE scmHandle = nullptr;
    SC_HANDLE serviceHandle = nullptr;
    bool success = false;

    if (!OpenServiceManager(scmHandle)) {
        return false;
    }

    if (!OpenServiceHandle(scmHandle, serviceHandle, SERVICE_QUERY_STATUS)) {
        CloseServiceHandle(scmHandle);
        return false;
    }

    SERVICE_STATUS svcStatus;
    if (QueryServiceStatus(serviceHandle, &svcStatus)) {
        status.currentState = svcStatus.dwCurrentState;
        status.win32ExitCode = svcStatus.dwWin32ExitCode;
        status.serviceExitCode = svcStatus.dwServiceSpecificExitCode;
        status.checkPoint = svcStatus.dwCheckPoint;
        status.waitHint = svcStatus.dwWaitHint;
        status.controlsAccepted = svcStatus.dwControlsAccepted;
        success = true;
    }
    else {
        LogError("QueryServiceStatus");
    }

    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);

    return success;
}

bool ServiceManager::IsInstalled() {
    SC_HANDLE scmHandle = nullptr;
    SC_HANDLE serviceHandle = nullptr;

    if (!OpenServiceManager(scmHandle)) {
        return false;
    }

    bool installed = OpenServiceHandle(scmHandle, serviceHandle, SERVICE_QUERY_STATUS);

    if (serviceHandle) {
        CloseServiceHandle(serviceHandle);
    }
    if (scmHandle) {
        CloseServiceHandle(scmHandle);
    }

    return installed;
}

bool ServiceManager::IsRunning() {
    ServiceStatus status;
    if (QueryStatus(status)) {
        return status.currentState == SERVICE_RUNNING;
    }
    return false;
}

void ServiceManager::ReportStatus(DWORD currentState, DWORD win32ExitCode, DWORD waitHint) {
    if (!statusHandle_) {
        return;
    }

    static DWORD checkPoint = 1;

    serviceStatus_.dwCurrentState = currentState;
    serviceStatus_.dwWin32ExitCode = win32ExitCode;
    serviceStatus_.dwWaitHint = waitHint;

    if (currentState == SERVICE_START_PENDING) {
        serviceStatus_.dwControlsAccepted = 0;
    }
    else {
        serviceStatus_.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }

    if ((currentState == SERVICE_RUNNING) || (currentState == SERVICE_STOPPED)) {
        serviceStatus_.dwCheckPoint = 0;
    }
    else {
        serviceStatus_.dwCheckPoint = checkPoint++;
    }

    SetServiceStatus(statusHandle_, &serviceStatus_);
}

void ServiceManager::RegisterServiceHandler(const std::wstring& serviceName) {
    serviceName_ = serviceName;
    statusHandle_ = RegisterServiceCtrlHandlerW(serviceName.c_str(),
        [](DWORD ctrlCode) {
            // This is a static callback, so we need a way to get back to the instance
            // In practice, you'd use a global or static pointer
        });
}

HANDLE ServiceManager::GetStopEvent() const {
    return stopEvent_;
}

void ServiceManager::SetCallbacks(VoidCallback onStart, VoidCallback onStop) {
    onStart_ = onStart;
    onStop_ = onStop;
}

void ServiceManager::ServiceMainProc(DWORD argc, LPTSTR* argv) {
    ReportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    if (onStart_) {
        onStart_();
    }

    ReportStatus(SERVICE_RUNNING, NO_ERROR, 0);

    // Wait for stop event
    WaitForSingleObject(stopEvent_, INFINITE);

    ReportStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

void ServiceManager::ServiceCtrlProc(DWORD ctrlCode) {
    switch (ctrlCode) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
        if (onStop_) {
            onStop_();
        }
        SetEvent(stopEvent_);
        break;

    case SERVICE_CONTROL_INTERROGATE:
        break;

    default:
        break;
    }
}

bool ServiceManager::OpenServiceManager(SC_HANDLE& scmHandle) {
    scmHandle = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scmHandle) {
        LogError("OpenSCManager");
        return false;
    }
    return true;
}

bool ServiceManager::OpenServiceHandle(SC_HANDLE scmHandle, SC_HANDLE& serviceHandle, DWORD desiredAccess) {
    ServiceConfig config;
    serviceHandle = OpenServiceW(scmHandle, config.serviceName.c_str(), desiredAccess);
    if (!serviceHandle) {
        LogError("OpenService");
        return false;
    }
    return true;
}

void ServiceManager::LogError(const std::string& operation) {
    if (platform_) {
        std::string errorMsg = operation + " failed: " + GetLastErrorString();
        platform_->logMessage(errorMsg);
    }
}

std::string ServiceManager::GetLastErrorString() {
    DWORD error = GetLastError();

    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&messageBuffer,
        0,
        NULL
    );

    std::string message(messageBuffer, size);
    LocalFree(messageBuffer);

    return "Error " + std::to_string(error) + ": " + message;
}

#endif // _WIN32