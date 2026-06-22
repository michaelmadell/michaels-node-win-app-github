#pragma once

#include <windows.h>
#include <memory>
#include <pdh.h>
#include <objbase.h>

struct HandleCloser {
    void operator()(HANDLE h) const {
        if (h != INVALID_HANDLE_VALUE && h != nullptr) {
            CloseHandle(h);
        }
    }
};

/**
 * @brief Smart pointer for Windows HANDLEs.
 * Example: g_stop_event = UniqueHandle(CreateEvent(...), HandleCloser());
 */
using UniqueHandle = std::unique_ptr<void, HandleCloser>;

struct PdhQueryCloser {
    void operator()(PDH_HQUERY h) const {
        if (h != nullptr) {
            PdhCloseQuery(h);
        }
    }
};
/**
 * @brief Smart pointer for PDH_HQUERY.
 * Example: m_hQuery = UniquePdhQuery(PdhOpenQuery(...), PdhQueryCloser());
 */
using UniquePdhQuery = std::unique_ptr<std::remove_pointer<PDH_HQUERY>::type, PdhQueryCloser>;

class ComInitializer {
    public:
        ComInitializer(DWORD dwCoInit = COINIT_MULTITHREADED) : hr_(E_FAIL) {
            hr_ = CoInitializeEx(nullptr, dwCoInit);
        }
        ~ComInitializer() {
            if (SUCCEEDED(hr_)) {
                CoUninitialize();
            }
        }
        bool Succeeded() const { return SUCCEEDED(hr_); }
        HRESULT GetHResult() const { return hr_; }
        ComInitializer(const ComInitializer&) = delete;
        ComInitializer& operator=(const ComInitializer&) = delete;
    
    private:
        HRESULT hr_;
};
