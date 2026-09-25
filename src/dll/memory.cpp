#include <windows.h>
#include "memory.h"
#include "veh_handler.h"
#include "breakpoint.h"
#include <cstring>

namespace veh {

MemoryManager& MemoryManager::Instance() {
	static MemoryManager instance;
	return instance;
}

// SEH를 사용하는 raw memcpy (C++ 객체 없는 함수에서만 사용)
bool SafeCopyMemory(void* dst, const void* src, size_t size) {
	__try {
		memcpy(dst, src, size);
		return true;
	}
	__except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION
		? EXCEPTION_EXECUTE_HANDLER
		: EXCEPTION_CONTINUE_SEARCH) {
		return false;
	}
}

std::vector<uint8_t> MemoryManager::Read(uint64_t address, uint32_t size) {
	std::vector<uint8_t> buffer(size);
	auto* src = reinterpret_cast<const void*>(address);

	if (!SafeCopyMemory(buffer.data(), src, size)) {
		buffer.clear();
	}

	return buffer;
}

bool MemoryManager::Write(uint64_t address, const uint8_t* data, uint32_t size) {
	DWORD oldProtect = 0;

	if (!MakeWritable(address, size, oldProtect)) {
		return false;
	}

	auto* dst = reinterpret_cast<void*>(address);
	bool success = SafeCopyMemory(dst, data, size);

	RestoreProtection(address, size, oldProtect);

	if (success) {
		FlushInstructionCache(GetCurrentProcess(), dst, size);
	}

	return success;
}

bool MemoryManager::MakeWritable(uint64_t address, uint32_t size, DWORD& oldProtect) {
	auto* ptr = reinterpret_cast<LPVOID>(address);
	return VirtualProtect(ptr, size, PAGE_EXECUTE_READWRITE, &oldProtect) != FALSE;
}

bool MemoryManager::RestoreProtection(uint64_t address, uint32_t size, DWORD oldProtect) {
	auto* ptr = reinterpret_cast<LPVOID>(address);
	DWORD dummy = 0;
	return VirtualProtect(ptr, size, oldProtect, &dummy) != FALSE;
}

uint64_t MemoryManager::Allocate(uint32_t size, uint32_t protection) {
	void* ptr = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, protection);
	return reinterpret_cast<uint64_t>(ptr);
}

bool MemoryManager::Free(uint64_t address, uint32_t /*size*/) {
	auto* ptr = reinterpret_cast<LPVOID>(address);
	return VirtualFree(ptr, 0, MEM_RELEASE) != FALSE;
}

// SEH wrapper context -- passed to shellcode thread
struct ShellcodeContext {
	void*    codeAddr;
	bool     crashed;
	uint32_t exceptionCode;
	uint64_t exceptionAddress;
};

// SEH wrapper must be in a separate function (no C++ destructors -- MSVC C2712)
static DWORD SafeCallShellcode(ShellcodeContext* ctx) {
	__try {
		auto fn = reinterpret_cast<DWORD(WINAPI*)(LPVOID)>(ctx->codeAddr);
		return fn(nullptr);
	} __except (
		ctx->crashed = true,
		ctx->exceptionCode = GetExceptionInformation()->ExceptionRecord->ExceptionCode,
		ctx->exceptionAddress = reinterpret_cast<uint64_t>(GetExceptionInformation()->ExceptionRecord->ExceptionAddress),
		EXCEPTION_EXECUTE_HANDLER
	) {
		return 0xDEAD0001;
	}
}

static DWORD WINAPI ShellcodeThreadProc(LPVOID param) {
	DWORD result = SafeCallShellcode(reinterpret_cast<ShellcodeContext*>(param));
	// Always unregister (covers fire-and-forget + normal paths; erase is idempotent)
	VehHandler::Instance().UnregisterShellcodeThread(GetCurrentThreadId());
	return result;
}

bool MemoryManager::ExecuteShellcode(const uint8_t* code, uint32_t size, uint32_t timeoutMs,
                                     uint64_t& allocAddr, uint32_t& exitCode,
                                     bool& crashed, uint32_t& exceptionCode, uint64_t& exceptionAddress) {
	crashed = false;
	exceptionCode = 0;
	exceptionAddress = 0;
	// 1. Allocate RWX page
	void* mem = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!mem) return false;
	allocAddr = reinterpret_cast<uint64_t>(mem);

	// 2. Copy shellcode
	memcpy(mem, code, size);
	FlushInstructionCache(GetCurrentProcess(), mem, size);

	// 3. Prepare context for SEH wrapper
	ShellcodeContext ctx = {};
	ctx.codeAddr = mem;

	// 4. Create thread suspended, register with VEH, then resume
	DWORD tid = 0;
	HANDLE hThread = CreateThread(nullptr, 0, ShellcodeThreadProc, &ctx, CREATE_SUSPENDED, &tid);
	if (!hThread) {
		VirtualFree(mem, 0, MEM_RELEASE);
		allocAddr = 0;
		return false;
	}
	VehHandler::Instance().RegisterShellcodeThread(tid);
	ResumeThread(hThread);

	if (timeoutMs == 0) {
		// Fire-and-forget: don't wait, don't free (caller manages)
		// Note: VEH registration stays until thread exits naturally
		CloseHandle(hThread);
		exitCode = 0;
		return true;
	}

	// 5. Wait for completion
	DWORD waitResult = WaitForSingleObject(hThread, timeoutMs);
	if (waitResult == WAIT_OBJECT_0) {
		DWORD code32 = 0;
		GetExitCodeThread(hThread, &code32);
		exitCode = code32;
	} else {
		// Timeout - terminate thread, then wait for actual termination
		TerminateThread(hThread, 0xDEAD);
		WaitForSingleObject(hThread, 5000);
		exitCode = 0xDEAD;
	}
	CloseHandle(hThread);
	VehHandler::Instance().UnregisterShellcodeThread(tid);

	// 6. Copy crash info from context
	if (ctx.crashed) {
		crashed = true;
		exceptionCode = ctx.exceptionCode;
		exceptionAddress = ctx.exceptionAddress;
	}

	// 7. Free RWX page (safe: thread is guaranteed dead at this point)
	VirtualFree(mem, 0, MEM_RELEASE);
	allocAddr = 0;

	return (waitResult == WAIT_OBJECT_0);
}

// Accessors for crash info from last ExecuteShellcode
// (pipe_server reads ShellcodeContext via response struct)

static void UserSpaceBounds(uint64_t start, uint64_t end, uint64_t& lo, uint64_t& hi) {
	SYSTEM_INFO si{};
	GetSystemInfo(&si);
	const uint64_t minApp = reinterpret_cast<uint64_t>(si.lpMinimumApplicationAddress);
	const uint64_t maxApp = reinterpret_cast<uint64_t>(si.lpMaximumApplicationAddress) + 1;
	lo = start > minApp ? start : minApp;
	hi = (end == 0 || end > maxApp) ? maxApp : end;
}

static bool IsReadable(DWORD protect) {
	return (protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0 && (protect & 0xFF) != 0;
}

static bool MatchesFilter(RegionFilter filter, bool value) {
	return filter == RegionFilter::Any || (filter == RegionFilter::Require) == value;
}

static uint8_t RegionTypeBit(DWORD type) {
	switch (type) {
	case MEM_IMAGE: return kRegionTypeImage;
	case MEM_MAPPED: return kRegionTypeMapped;
	default: return kRegionTypePrivate;
	}
}

uint64_t MemoryManager::QueryMap(uint64_t start, uint64_t end, uint32_t maxRegions, bool includeFree,
                                 std::vector<MemoryRegionEntry>& out) {
	uint64_t addr, hi;
	UserSpaceBounds(start, end, addr, hi);
	while (addr < hi) {
		MEMORY_BASIC_INFORMATION mbi{};
		if (!VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) break;
		const uint64_t base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
		const uint64_t next = base + mbi.RegionSize;
		if (next <= addr) break;
		if (includeFree || mbi.State != MEM_FREE) {
			if (out.size() >= maxRegions) return addr;
			out.push_back({base, reinterpret_cast<uint64_t>(mbi.AllocationBase), mbi.RegionSize,
			               mbi.State, mbi.Protect, mbi.AllocationProtect, mbi.Type});
		}
		addr = next;
	}
	return 0;
}

bool MemoryManager::Search(const SearchMemoryRequest& req, const uint8_t* pattern, const uint8_t* mask,
                           uint64_t excludeStart, uint64_t excludeEnd, SearchResult& result) {
	const size_t n = req.patternSize;
	const uint32_t align = req.alignment ? req.alignment : 1;
	constexpr size_t kChunk = 1 << 20;

	// The scan buffer and the masked pattern live in one private allocation that is
	// skipped by AllocationBase, so the scanner never finds its own copies.
	const size_t scratchSize = kChunk + n;
	auto* scratch = static_cast<uint8_t*>(VirtualAlloc(nullptr, scratchSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!scratch) return false;
	uint8_t* buf = scratch;
	uint8_t* pat = scratch + kChunk;
	size_t anchor = n;
	for (size_t k = 0; k < n; ++k) {
		pat[k] = pattern[k] & mask[k];
		if (anchor == n && mask[k] == 0xFF) anchor = k;
	}

	auto matchesAt = [&](const uint8_t* p) {
		for (size_t k = 0; k < n; ++k)
			if ((p[k] & mask[k]) != pat[k]) return false;
		return true;
	};

	uint64_t addr, hi;
	UserSpaceBounds(req.startAddress, req.endAddress, addr, hi);
	bool full = false;
	while (addr < hi && !full) {
		MEMORY_BASIC_INFORMATION mbi{};
		if (!VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) break;
		const uint64_t base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
		const uint64_t next = base + mbi.RegionSize;
		if (next <= addr) break;
		const uint64_t regionEnd = next < hi ? next : hi;
		const bool eligible = mbi.State == MEM_COMMIT && IsReadable(mbi.Protect)
			&& mbi.AllocationBase != scratch
			&& MatchesFilter(req.writable, (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY
				| PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0)
			&& MatchesFilter(req.executable, (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ
				| PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0)
			&& (req.typeMask == 0 || (req.typeMask & RegionTypeBit(mbi.Type)) != 0);
		if (eligible && regionEnd - addr >= n) {
			result.regionsScanned++;
			for (uint64_t pos = addr; pos + n <= regionEnd && !full;) {
				const size_t len = static_cast<size_t>((regionEnd - pos) < kChunk ? (regionEnd - pos) : kChunk);
				if (!SafeCopyMemory(buf, reinterpret_cast<const void*>(pos), len)) break;
				BreakpointManager::Instance().MaskBreakpointsInBuffer(pos, buf, len);
				result.scannedBytes += len;
				const size_t last = len - n;
				auto consider = [&](size_t i) {
					const uint64_t hit = pos + i;
					if (hit % align != 0 || (hit >= excludeStart && hit < excludeEnd) || !matchesAt(buf + i))
						return;
					if (result.hits.size() >= req.maxResults) {
						result.nextAddress = hit;
						full = true;
						return;
					}
					result.hits.push_back(hit);
				};
				if (anchor < n) {
					const uint8_t* p = buf + anchor;
					const uint8_t* stop = buf + last + anchor + 1;
					while (!full && p < stop) {
						p = static_cast<const uint8_t*>(memchr(p, pat[anchor], stop - p));
						if (!p) break;
						consider(static_cast<size_t>(p - buf) - anchor);
						++p;
					}
				} else {
					for (size_t i = 0; i <= last && !full; ++i) consider(i);
				}
				if (pos + len >= regionEnd) break;
				pos += len - (n - 1);
			}
		}
		addr = next;
	}

	VirtualFree(scratch, 0, MEM_RELEASE);
	return true;
}

} // namespace veh
