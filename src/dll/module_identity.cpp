#include <windows.h>
#include <psapi.h>
#include <bcrypt.h>
#include <array>
#include <atomic>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include "module_identity.h"
#include "stack_walk.h"
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "psapi.lib")

namespace veh {
namespace {
struct File { HANDLE handle = INVALID_HANDLE_VALUE; ~File() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); } };
struct Hash {
    BCRYPT_HASH_HANDLE hash = nullptr;
    ~Hash() { if (hash) BCryptDestroyHash(hash); }
};
BCRYPT_ALG_HANDLE algorithm = nullptr; // one process-lifetime provider, warmed before Ready
std::atomic<bool> trackingAvailable{false};
struct CachedIdentity { BY_HANDLE_FILE_INFORMATION file{}; uint64_t epoch = 0; GetModuleIdentityResponse value{}; };
std::mutex cacheMutex;
std::map<uint64_t, CachedIdentity> cache;
}

void SetModuleIdentityTracking(bool available) {
    if (available) StackWalker::Instance().NotifyModulesChanged(0);
    trackingAvailable.store(available, std::memory_order_release);
}

void PrepareModuleIdentity() {
    if (algorithm) return;
    BCRYPT_ALG_HANDLE opened = nullptr;
    if (BCryptOpenAlgorithmProvider(&opened, BCRYPT_SHA256_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0) < 0) return;
    // Provider loading and first-use initialization must never happen while a
    // debugger module-load stop holds the loader lock. Keep the provider alive.
    Hash warm; uint8_t digest[32]{};
    if (BCryptCreateHash(opened, &warm.hash, nullptr, 0, nullptr, 0, 0) < 0 ||
            BCryptHashData(warm.hash, digest, 1, 0) < 0 || BCryptFinishHash(warm.hash, digest, sizeof(digest), 0) < 0) {
        if (warm.hash) { BCryptDestroyHash(warm.hash); warm.hash = nullptr; }
        BCryptCloseAlgorithmProvider(opened, 0); return;
    }
    algorithm = opened;
}

GetModuleIdentityResponse InspectModuleIdentity(uint64_t base) {
    GetModuleIdentityResponse out{}; out.status = IpcStatus::Error; out.moduleBase = base;
    if (!trackingAvailable.load(std::memory_order_acquire)) { out.status = IpcStatus::InvalidState; return out; }
    out.moduleEpoch = StackWalker::Instance().ModuleEpoch();
    if (!base) { out.status = IpcStatus::Ok; return out; }
    if (base > UINTPTR_MAX) { out.status = IpcStatus::InvalidArgs; return out; }
    if (!algorithm) return out;
    const auto image = reinterpret_cast<void*>(static_cast<uintptr_t>(base));
    MEMORY_BASIC_INFORMATION region{};
    if (!VirtualQuery(image, &region, sizeof(region)) || region.Type != MEM_IMAGE || region.AllocationBase != image) return out;
    const auto epoch = StackWalker::Instance().ModuleEpoch();
    out.moduleEpoch = epoch;
    // Query the mapped file, not a same-name file in the frontend or DLL search path.
    std::array<wchar_t, 32768> path{};
    const DWORD length = GetMappedFileNameW(GetCurrentProcess(), image, path.data(), static_cast<DWORD>(path.size()));
    if (!length || length >= path.size() || std::wstring(path.data()).rfind(L"\\Device\\", 0) != 0) return out;
    const auto name = std::wstring(L"\\\\?\\GLOBALROOT") + path.data();
    File file; file.handle = CreateFileW(name.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    BY_HANDLE_FILE_INFORMATION info{};
    if (file.handle == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(file.handle, &info) ||
            info.nFileSizeHigh || !info.nFileSizeLow || info.nFileSizeLow > 256u * 1024u * 1024u) return out;
    std::array<uint8_t, 4096> disk{}, memory{}; DWORD count = 0; SIZE_T copied = 0;
    if (!ReadFile(file.handle, disk.data(), static_cast<DWORD>(disk.size()), &count, nullptr) || count < 256) return out;
    IMAGE_DOS_HEADER dos{}; std::memcpy(&dos, disk.data(), sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0 || static_cast<size_t>(dos.e_lfanew) > count - 88) return out;
    const auto nt = static_cast<size_t>(dos.e_lfanew);
    DWORD signature = 0, imageSize = 0, headerSize = 0; WORD magic = 0;
    std::memcpy(&signature, disk.data() + nt, 4);
    std::memcpy(&magic, disk.data() + nt + 24, 2);
    std::memcpy(&imageSize, disk.data() + nt + 24 + 56, 4);
    std::memcpy(&headerSize, disk.data() + nt + 24 + 60, 4);
    if (signature != IMAGE_NT_SIGNATURE || (magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) ||
            headerSize < nt + 88 || headerSize > count || !imageSize ||
            !ReadProcessMemory(GetCurrentProcess(), image, memory.data(), headerSize, &copied) || copied != headerSize) return out;
    // Windows may rewrite OptionalHeader.ImageBase to the ASLR load address.
    // Accept only the real load address or preferred base before normalizing it.
    const size_t imageBaseOffset = nt + 24 + (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? 28 : 24);
    const size_t baseWidth = magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? 4 : 8;
    uint64_t loadedBase = 0, preferredBase = 0;
    std::memcpy(&loadedBase, memory.data() + imageBaseOffset, baseWidth);
    std::memcpy(&preferredBase, disk.data() + imageBaseOffset, baseWidth);
    if (loadedBase != base && loadedBase != preferredBase) return out;
    std::memcpy(memory.data() + imageBaseOffset, disk.data() + imageBaseOffset, baseWidth);
    if (std::memcmp(memory.data(), disk.data(), headerSize)) return out;
    out.addressBits = magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? 32 : 64; out.imageSize = imageSize;
    std::lock_guard<std::mutex> lock(cacheMutex);
    const auto found = cache.find(base);
    if (found != cache.end() && found->second.epoch == epoch &&
            !std::memcmp(&found->second.file, &info, sizeof(info)) && trackingAvailable.load(std::memory_order_acquire) &&
            epoch == StackWalker::Instance().ModuleEpoch()) return found->second.value;
    LARGE_INTEGER start{};
    if (!SetFilePointerEx(file.handle, start, nullptr, FILE_BEGIN)) return out;
    Hash hash;
    if (BCryptCreateHash(algorithm, &hash.hash, nullptr, 0, nullptr, 0, 0) < 0) return out;
    std::array<uint8_t, 65536> block{}; uint64_t total = 0;
    for (;;) {
        if (!ReadFile(file.handle, block.data(), static_cast<DWORD>(block.size()), &count, nullptr)) return out;
        if (!count) break;
        total += count;
        if (total > info.nFileSizeLow || BCryptHashData(hash.hash, block.data(), count, 0) < 0) return out;
    }
    if (total != info.nFileSizeLow || BCryptFinishHash(hash.hash, out.sha256, sizeof(out.sha256), 0) < 0 ||
            epoch != StackWalker::Instance().ModuleEpoch() || !trackingAvailable.load(std::memory_order_acquire)) return out;
    out.status = IpcStatus::Ok;
    if (cache.size() >= 64) cache.clear();
    cache[base] = {info, epoch, out};
    return out;
}
} // namespace veh
