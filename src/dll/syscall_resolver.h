#pragma once
#include <windows.h>
#include <cstdint>

// NTSTATUS -- <winternl.h> 충돌 방지를 위해 직접 정의
#ifndef _NTSTATUS_DEFINED
#define _NTSTATUS_DEFINED
typedef LONG NTSTATUS;
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

namespace veh {

// NtCreateEvent의 EVENT_TYPE
enum NtEventType {
	NtNotificationEvent = 0,   // manual-reset
	NtSynchronizationEvent = 1 // auto-reset
};

// ntdll syscall stub 복사본을 통한 안전한 syscall 호출.
// VEH 핸들러 경로에서 WinAPI에 BP가 걸려있어도
// 복사본을 호출하므로 재진입 crash를 방지한다.
//
// Initialize()는 반드시 VEH handler Install 전에 호출할 것.
class SyscallResolver {
public:
	static SyscallResolver& Instance();

	bool Initialize();
	void Shutdown();
	bool IsInitialized() const { return initialized_; }

	// --- VirtualProtect 대체 ---
	NTSTATUS ProtectVirtualMemory(
		PVOID* baseAddress, PSIZE_T regionSize,
		ULONG newProtect, PULONG oldProtect);

	// --- FlushInstructionCache 대체 ---
	NTSTATUS FlushInstructionCache(PVOID baseAddress, SIZE_T length);

	// --- WaitForSingleObject 대체 ---
	// timeout: nullptr = INFINITE
	NTSTATUS WaitForSingleObject(HANDLE handle, PLARGE_INTEGER timeout);

	// --- CreateEventW 대체 (auto-reset, non-signaled) ---
	NTSTATUS CreateEvent(PHANDLE eventHandle);

	// --- CloseHandle 대체 ---
	NTSTATUS Close(HANDLE handle);

	// --- SetEvent 대체 ---
	NTSTATUS SetEvent(HANDLE handle);

private:
	// 스텁 파싱 결과
	struct StubInfo {
		uint32_t size;  // ret 포함 스텁 전체 크기
		uint32_t ssn;   // 추출된 SSN (0xFFFFFFFF = 실패)
	};

	StubInfo ParseStub(const uint8_t* stub, uint32_t maxLen);

	// 명령어 길이 디코더
	struct InsnInfo {
		uint8_t length;
		uint8_t opcode;
		bool    hasRexW;
	};
	static InsnInfo DecodeInsn(const uint8_t* code, uint32_t maxLen);

	// 단일 함수 스텁 복사. 반환: 사용한 바이트 수 (0 = 실패)
	size_t CopyOneStub(const char* funcName, uint8_t* dest, size_t destRemaining, void** outFunc);

	// 실행 가능 메모리
	void* execPage_ = nullptr;
	static constexpr size_t kExecPageSize = 4096;

	// --- 함수 포인터 (스텁 복사본) ---
	using FnProtectVirtualMemory = NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
	using FnFlushInstructionCache = NTSTATUS(NTAPI*)(HANDLE, PVOID, SIZE_T);
	using FnWaitForSingleObject = NTSTATUS(NTAPI*)(HANDLE, BOOLEAN, PLARGE_INTEGER);
	using FnCreateEvent = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, DWORD, BOOLEAN);
	using FnClose = NTSTATUS(NTAPI*)(HANDLE);
	using FnSetEvent = NTSTATUS(NTAPI*)(HANDLE, PLONG);

	FnProtectVirtualMemory pfnProtectVM_ = nullptr;
	FnFlushInstructionCache pfnFlushIC_ = nullptr;
	FnWaitForSingleObject pfnWaitSingle_ = nullptr;
	FnCreateEvent pfnCreateEvent_ = nullptr;
	FnClose pfnClose_ = nullptr;
	FnSetEvent pfnSetEvent_ = nullptr;

	bool initialized_ = false;
};

// ---------------------------------------------------------------------------
// TEB 직접 접근 인라인 함수
// syscall이 아닌 유저모드 함수 (TlsGetValue, TlsSetValue, GetLastError)를
// TEB 직접 읽기/쓰기로 대체. 함수 호출 자체가 없으므로 BP 문제 완전 회피.
// ---------------------------------------------------------------------------

// TEB TLS 오프셋
// TlsSlots[64]: index 0~63 직접 접근
// TlsExpansionSlots: index 64~1088 (포인터를 읽고 간접 접근)
#ifdef _WIN64
static constexpr size_t kTebTlsSlotsOffset = 0x1480;
static constexpr size_t kTebTlsExpansionOffset = 0x1780;
static constexpr size_t kTebLastErrorOffset = 0x68;
static constexpr size_t kTlsSlotSize = 8;
#else
static constexpr size_t kTebTlsSlotsOffset = 0xE10;
static constexpr size_t kTebTlsExpansionOffset = 0xF94;
static constexpr size_t kTebLastErrorOffset = 0x34;
static constexpr size_t kTlsSlotSize = 4;
#endif

inline uint8_t* GetTebPtr() {
#ifdef _WIN64
	return reinterpret_cast<uint8_t*>(__readgsqword(0x30));
#else
	return reinterpret_cast<uint8_t*>(__readfsdword(0x18));
#endif
}

inline LPVOID SafeTlsGetValue(DWORD index) {
	auto* teb = GetTebPtr();
	if (index < TLS_MINIMUM_AVAILABLE) {
		return *reinterpret_cast<LPVOID*>(teb + kTebTlsSlotsOffset + index * kTlsSlotSize);
	}
	// 확장 슬롯 (index 64~1088) -- TEB.TlsExpansionSlots 포인터 경유
	auto* expansionSlots = *reinterpret_cast<LPVOID**>(teb + kTebTlsExpansionOffset);
	if (!expansionSlots) return nullptr;
	return expansionSlots[index - TLS_MINIMUM_AVAILABLE];
}

inline BOOL SafeTlsSetValue(DWORD index, LPVOID value) {
	auto* teb = GetTebPtr();
	if (index < TLS_MINIMUM_AVAILABLE) {
		*reinterpret_cast<LPVOID*>(teb + kTebTlsSlotsOffset + index * kTlsSlotSize) = value;
		return TRUE;
	}
	auto* expansionSlots = *reinterpret_cast<LPVOID**>(teb + kTebTlsExpansionOffset);
	if (!expansionSlots) return FALSE;
	expansionSlots[index - TLS_MINIMUM_AVAILABLE] = value;
	return TRUE;
}

inline DWORD SafeGetLastError() {
#ifdef _WIN64
	auto* teb = reinterpret_cast<uint8_t*>(__readgsqword(0x30));
#else
	auto* teb = reinterpret_cast<uint8_t*>(__readfsdword(0x18));
#endif
	return *reinterpret_cast<DWORD*>(teb + kTebLastErrorOffset);
}

} // namespace veh
