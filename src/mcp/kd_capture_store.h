#pragma once
#include "../common/kd_trace_protocol.h"
#include <windows.h>
#include <nlohmann/json.hpp>
#include <string>
#include <stdexcept>
#include <vector>

namespace veh {
// A bounded disk spool owns raw facts; only a chunk lives on the heap. Mapping
// permits two-pass pure decoding without retaining one C++ object per step.
using KdCaptureWrite = BOOL (*)(HANDLE,const void*,DWORD,DWORD*);
class KdCaptureStore {
public:
    KdCaptureStore(uint32_t steps,uint32_t flags,uint64_t start,uint64_t end,const std::string& output,KdCaptureWrite write=nullptr);
    ~KdCaptureStore();
    KdCaptureStore(const KdCaptureStore&)=delete;
    KdCaptureStore& operator=(const KdCaptureStore&)=delete;
    bool Append(const kdtrace::Record* records,uint32_t count,uint64_t generation,uint32_t cpu);
    bool Map();
    size_t size() const {return static_cast<size_t>(header_.records);}
    const kdtrace::Record& operator[](size_t index) const;
    nlohmann::json Keep(bool complete);
    const std::string& Path() const {return path_;}
private:
    bool WriteHeader();
    bool WriteBytes(const void* data,DWORD bytes,DWORD* written);
    bool RepairPrefix();
    HANDLE file_=INVALID_HANDLE_VALUE,mapping_=nullptr;
    const uint8_t* view_=nullptr;
    std::wstring wide_;
    std::string path_;
    kdtrace::CaptureFileHeader header_={};
    bool keep_=false,needsRepair_=false;
    KdCaptureWrite write_=nullptr;
};
// Reject Win32 path truncation/control characters before any filesystem or target effects.
std::string ValidateKdCapturePath(const std::string& path, size_t maxBytes=4096);
nlohmann::json ReadKdCapture(const nlohmann::json& args);
} // namespace veh
