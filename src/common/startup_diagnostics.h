#pragma once
#include <windows.h>
#include <cstdint>
#include <cstdlib>
#include <cerrno>

namespace veh {
// Separate from target IPC: one fixed record, before Ready, on an inherited pipe.
// Never send text, paths, logs or credentials through this channel.
enum class StartupError : uint32_t {
    BackendUnavailable = 1, VersionMismatch = 2, TargetUnavailable = 3,
    IpcSetupFailed = 4, InvalidConfiguration = 5,
};
enum class StartupDetail : uint32_t {
    DriverOpenFailed = 1, HypervisorNotRunning = 2, AbiMismatch = 3,
    TargetOpenFailed = 4, PipeCreateFailed = 5, InvalidArguments = 6,
    BackendBusy = 7, // the backend serves one session at a time and another holds it
};
inline constexpr wchar_t kStartupDiagnosticHandle[] = L"VEH_STARTUP_DIAGNOSTIC_HANDLE";
struct StartupDiagnostic {
    uint32_t magic = 0x31534456; // VDS1
    uint16_t version = 1;
    uint16_t size = 24;
    StartupError error = StartupError::BackendUnavailable;
    StartupDetail detail = StartupDetail::DriverOpenFailed;
    uint32_t systemError = 0;
    uint32_t reserved = 0;
};
static_assert(sizeof(StartupDiagnostic) == 24);
inline const char* StartupErrorName(StartupError error) {
    switch (error) {
    case StartupError::BackendUnavailable: return "backend_unavailable";
    case StartupError::VersionMismatch: return "version_mismatch";
    case StartupError::TargetUnavailable: return "target_unavailable";
    case StartupError::IpcSetupFailed: return "ipc_setup_failed";
    case StartupError::InvalidConfiguration: return "invalid_configuration";
    default: return nullptr;
    }
}
inline const char* StartupDetailName(StartupDetail detail) {
    switch (detail) {
    case StartupDetail::DriverOpenFailed: return "driver_open_failed";
    case StartupDetail::HypervisorNotRunning: return "hypervisor_not_running";
    case StartupDetail::AbiMismatch: return "abi_mismatch";
    case StartupDetail::TargetOpenFailed: return "target_open_failed";
    case StartupDetail::PipeCreateFailed: return "pipe_create_failed";
    case StartupDetail::InvalidArguments: return "invalid_arguments";
    case StartupDetail::BackendBusy: return "backend_busy";
    default: return nullptr;
    }
}
inline bool ValidStartupDiagnostic(const StartupDiagnostic& record) {
    if (record.magic != 0x31534456 || record.version != 1 ||
        record.size != sizeof(record) || record.reserved) return false;
    switch (record.detail) {
    case StartupDetail::DriverOpenFailed:
    case StartupDetail::HypervisorNotRunning:
    case StartupDetail::BackendBusy: return record.error == StartupError::BackendUnavailable;
    case StartupDetail::AbiMismatch: return record.error == StartupError::VersionMismatch;
    case StartupDetail::TargetOpenFailed: return record.error == StartupError::TargetUnavailable;
    case StartupDetail::PipeCreateFailed: return record.error == StartupError::IpcSetupFailed;
    case StartupDetail::InvalidArguments: return record.error == StartupError::InvalidConfiguration;
    default: return false;
    }
}
// Optional, best effort. Call once on an early failure, then keep the original exit code.
// Unaware/old runners supply no handle, so the normal exit path remains unchanged.
inline bool ReportStartupFailure(StartupError error, StartupDetail detail, uint32_t systemError = 0) {
    const DWORD savedError = GetLastError();
    wchar_t value[32]{};
    const DWORD length = GetEnvironmentVariableW(kStartupDiagnosticHandle, value, 32);
    if (!length || length >= 32) { SetLastError(savedError); return false; }
    SetEnvironmentVariableW(kStartupDiagnosticHandle, nullptr); // one report; not for descendants
    wchar_t* end = nullptr;
    errno = 0;
    const auto number = _wcstoui64(value, &end, 10);
    if (errno || !number || !end || *end || value[0] < L'0' || value[0] > L'9' ||
        number > static_cast<uint64_t>(UINTPTR_MAX)) { SetLastError(savedError); return false; }
    HANDLE pipe = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(number));
    SetHandleInformation(pipe, HANDLE_FLAG_INHERIT, 0);
    StartupDiagnostic record;
    record.error = error; record.detail = detail; record.systemError = systemError;
    DWORD written = 0;
    const bool ok = GetFileType(pipe) == FILE_TYPE_PIPE && ValidStartupDiagnostic(record) &&
        WriteFile(pipe, &record, sizeof(record), &written, nullptr) && written == sizeof(record);
    CloseHandle(pipe);
    SetLastError(savedError);
    return ok;
}
} // namespace veh
