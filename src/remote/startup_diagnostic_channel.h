#pragma once
#include "common/startup_diagnostics.h"
#include <algorithm>
#include <string>
#include <memory>
#include <vector>

namespace veh::remote {
// Only the diagnostic writer, and an optional operator-configured stderr log, are
// inherited. Never make runner sockets, token files, work handles or unrelated
// process handles inheritable for an agent.
class StartupDiagnosticChannel {
public:
    ~StartupDiagnosticChannel() { Close(); }
    StartupDiagnosticChannel() = default;
    StartupDiagnosticChannel(const StartupDiagnosticChannel&) = delete;
    StartupDiagnosticChannel& operator=(const StartupDiagnosticChannel&) = delete;
    void Close() { if (reader_) CloseHandle(reader_); reader_ = nullptr; }
    // stderrFile: empty, or a local log the agent's stderr is appended to. The runner
    // never reads it, so a chatty agent cannot block on an undrained pipe.
    bool CreateAgent(const std::wstring& executable, wchar_t* command, const std::wstring& stderrFile,
        PROCESS_INFORMATION& process) {
        SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
        struct Resources {
            HANDLE handles[2]{};
            HANDLE& writer = handles[0];
            HANDLE& log = handles[1];
            LPPROC_THREAD_ATTRIBUTE_LIST attributes = nullptr;
            std::vector<unsigned char> storage;
            ~Resources() {
                const DWORD error = GetLastError();
                if (attributes) DeleteProcThreadAttributeList(attributes);
                if (writer) CloseHandle(writer);
                if (log) CloseHandle(log);
                SetLastError(error);
            }
        } resources;
        if (!stderrFile.empty()) {
            const HANDLE log = CreateFileW(stderrFile.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE |
                FILE_SHARE_DELETE, &security, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (log == INVALID_HANDLE_VALUE) return false;
            resources.log = log;
        }
        if (!CreatePipe(&reader_, &resources.writer, &security, sizeof(StartupDiagnostic))) return false;
        DWORD failure = 0;
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
        resources.storage.resize(bytes);
        auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(resources.storage.data());
        bool created = false;
        do {
            if (!SetHandleInformation(reader_, HANDLE_FLAG_INHERIT, 0)) { failure = GetLastError(); break; }
            if (!InitializeProcThreadAttributeList(attributes, 1, 0, &bytes)) { failure = GetLastError(); break; }
            resources.attributes = attributes;
            const SIZE_T handleCount = resources.log ? 2 : 1;
            if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    resources.handles, handleCount * sizeof(HANDLE), nullptr, nullptr)) { failure = GetLastError(); break; }
            // Build a private child environment; do not mutate the resident's environment.
            auto releaseEnvironment = [](wchar_t* block) { FreeEnvironmentStringsW(block); };
            std::unique_ptr<wchar_t, decltype(releaseEnvironment)> inherited(GetEnvironmentStringsW(), releaseEnvironment);
            if (!inherited) { failure = GetLastError(); break; }
            std::vector<std::wstring> entries;
            for (const wchar_t* entry = inherited.get(); *entry; entry += wcslen(entry) + 1) {
                const std::wstring value(entry);
                const auto equals = value.find(L'=');
                if (equals != std::wstring::npos &&
                    _wcsicmp(value.substr(0, equals).c_str(), kStartupDiagnosticHandle) == 0) continue;
                entries.push_back(value);
            }
            entries.push_back(std::wstring(kStartupDiagnosticHandle) + L"=" +
                std::to_wstring(reinterpret_cast<uintptr_t>(resources.writer)));
            std::sort(entries.begin(), entries.end(),
                [](const auto& a, const auto& b) { return _wcsicmp(a.c_str(), b.c_str()) < 0; });
            std::vector<wchar_t> environment;
            for (const auto& entry : entries) {
                environment.insert(environment.end(), entry.begin(), entry.end());
                environment.push_back(0);
            }
            environment.push_back(0);
            STARTUPINFOEXW startup{};
            startup.StartupInfo.cb = sizeof(startup);
            startup.lpAttributeList = attributes;
            if (resources.log) {
                startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
                startup.StartupInfo.hStdError = resources.log;
            }
            created = CreateProcessW(executable.c_str(), command, nullptr, nullptr, TRUE,
                CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                environment.data(), nullptr, &startup.StartupInfo, &process) != FALSE;
            if (!created) failure = GetLastError();
        } while (false);
        if (!created) { Close(); SetLastError(failure); }
        return created;
    }
    bool Read(StartupDiagnostic& record) const {
        DWORD available = 0, received = 0;
        // No wait for EOF, and no blocking read of an untrusted length.
        return reader_ && PeekNamedPipe(reader_, nullptr, 0, nullptr, &available, nullptr) &&
            available == sizeof(record) && ReadFile(reader_, &record, sizeof(record), &received, nullptr) &&
            received == sizeof(record) && ValidStartupDiagnostic(record);
    }
private:
    HANDLE reader_ = nullptr;
};
} // namespace veh::remote
