#include "injector.h"
#include "logger.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <filesystem>

// NtCreateThreadEx 타입 정의
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef NTAPI
#define NTAPI __stdcall
#endif

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	PVOID ObjectAttributes,
	HANDLE ProcessHandle,
	PVOID StartRoutine,
	PVOID Argument,
	ULONG CreateFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	PVOID AttributeList
);

namespace veh {

InjectionMethod ParseInjectionMethod(const std::string& str) {
	if (str == "createRemoteThread") return InjectionMethod::CreateRemoteThread;
	if (str == "ntCreateThreadEx")   return InjectionMethod::NtCreateThreadEx;
	if (str == "threadHijack")       return InjectionMethod::ThreadHijack;
	if (str == "queueUserApc")       return InjectionMethod::QueueUserAPC;
	return InjectionMethod::Auto;
}

// --- 공통 헬퍼 ---

bool Injector::EnableDebugPrivilege() {
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
		return false;

	LUID luid;
	if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
		CloseHandle(token);
		return false;
	}

	TOKEN_PRIVILEGES tp = {};
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	bool result = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
	CloseHandle(token);
	return result && GetLastError() == ERROR_SUCCESS;
}

LPVOID Injector::AllocRemoteString(HANDLE process, const std::string& str) {
	size_t size = str.size() + 1;
	LPVOID remote = VirtualAllocEx(process, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!remote) {
		LOG_ERROR("VirtualAllocEx failed: %u", GetLastError());
		return nullptr;
	}
	if (!WriteProcessMemory(process, remote, str.c_str(), size, nullptr)) {
		LOG_ERROR("WriteProcessMemory failed: %u", GetLastError());
		VirtualFreeEx(process, remote, 0, MEM_RELEASE);
		return nullptr;
	}
	return remote;
}

void Injector::FreeRemoteString(HANDLE process, LPVOID remoteMem) {
	if (remoteMem) VirtualFreeEx(process, remoteMem, 0, MEM_RELEASE);
}

// --- WoW64 원격 LoadLibraryA 주소 찾기 ---

FARPROC Injector::GetRemoteLoadLibraryA(HANDLE process) {
	// WoW64 프로세스의 32비트 kernel32에서 LoadLibraryA 주소를 찾는다.
	// 방법: EnumProcessModulesEx(LIST_MODULES_32BIT) → kernel32 base → export table 파싱

	HMODULE modules[1024];
	DWORD needed = 0;
	if (!EnumProcessModulesEx(process, modules, sizeof(modules), &needed, LIST_MODULES_32BIT)) {
		LOG_ERROR("[WoW64] EnumProcessModulesEx failed: %u", GetLastError());
		return nullptr;
	}

	HMODULE kernel32Base = nullptr;
	DWORD count = needed / sizeof(HMODULE);
	for (DWORD i = 0; i < count; i++) {
		char modName[MAX_PATH] = {};
		if (GetModuleBaseNameA(process, modules[i], modName, sizeof(modName))) {
			if (_stricmp(modName, "kernel32.dll") == 0) {
				kernel32Base = modules[i];
				break;
			}
		}
	}

	if (!kernel32Base) {
		LOG_ERROR("[WoW64] 32-bit kernel32.dll not found in target");
		return nullptr;
	}

	LOG_DEBUG("[WoW64] 32-bit kernel32 base: 0x%p", kernel32Base);

	// Read DOS header + validate magic
	IMAGE_DOS_HEADER dosHeader;
	if (!ReadProcessMemory(process, kernel32Base, &dosHeader, sizeof(dosHeader), nullptr)) {
		LOG_ERROR("[WoW64] Failed to read DOS header");
		return nullptr;
	}
	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		LOG_ERROR("[WoW64] Invalid DOS signature: 0x%04X", dosHeader.e_magic);
		return nullptr;
	}

	// Read PE header (32-bit) + validate signature
	IMAGE_NT_HEADERS32 ntHeaders;
	if (!ReadProcessMemory(process, (BYTE*)kernel32Base + dosHeader.e_lfanew,
		&ntHeaders, sizeof(ntHeaders), nullptr)) {
		LOG_ERROR("[WoW64] Failed to read NT headers");
		return nullptr;
	}
	if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
		LOG_ERROR("[WoW64] Invalid NT signature: 0x%08X", ntHeaders.Signature);
		return nullptr;
	}

	// Export directory
	DWORD exportRva = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (!exportRva) {
		LOG_ERROR("[WoW64] No export directory");
		return nullptr;
	}

	IMAGE_EXPORT_DIRECTORY exportDir;
	if (!ReadProcessMemory(process, (BYTE*)kernel32Base + exportRva,
		&exportDir, sizeof(exportDir), nullptr)) {
		LOG_ERROR("[WoW64] Failed to read export directory");
		return nullptr;
	}

	// Sanity check export counts
	if (exportDir.NumberOfNames > 100000 || exportDir.NumberOfFunctions > 100000) {
		LOG_ERROR("[WoW64] Suspicious export count: names=%u funcs=%u",
			exportDir.NumberOfNames, exportDir.NumberOfFunctions);
		return nullptr;
	}

	// Read name RVAs, ordinals, function RVAs
	std::vector<DWORD> nameRvas(exportDir.NumberOfNames);
	std::vector<WORD> ordinals(exportDir.NumberOfNames);
	std::vector<DWORD> funcRvas(exportDir.NumberOfFunctions);

	if (!ReadProcessMemory(process, (BYTE*)kernel32Base + exportDir.AddressOfNames,
		nameRvas.data(), nameRvas.size() * sizeof(DWORD), nullptr) ||
		!ReadProcessMemory(process, (BYTE*)kernel32Base + exportDir.AddressOfNameOrdinals,
		ordinals.data(), ordinals.size() * sizeof(WORD), nullptr) ||
		!ReadProcessMemory(process, (BYTE*)kernel32Base + exportDir.AddressOfFunctions,
		funcRvas.data(), funcRvas.size() * sizeof(DWORD), nullptr)) {
		LOG_ERROR("[WoW64] Failed to read export tables");
		return nullptr;
	}

	for (DWORD i = 0; i < exportDir.NumberOfNames; i++) {
		char funcName[64] = {};
		ReadProcessMemory(process, (BYTE*)kernel32Base + nameRvas[i],
			funcName, sizeof(funcName) - 1, nullptr);
		if (strcmp(funcName, "LoadLibraryA") == 0) {
			WORD ord = ordinals[i];
			if (ord >= exportDir.NumberOfFunctions) continue;
			FARPROC addr = (FARPROC)((BYTE*)kernel32Base + funcRvas[ord]);
			LOG_INFO("[WoW64] LoadLibraryA at 0x%p", addr);
			return addr;
		}
	}

	LOG_ERROR("[WoW64] LoadLibraryA not found in export table");
	return nullptr;
}

// --- 방식 1: CreateRemoteThread ---

bool Injector::InjectViaCreateRemoteThread(HANDLE process, LPVOID remoteStr, FARPROC loadLib) {

	HANDLE thread = ::CreateRemoteThread(process, nullptr, 0,
		(LPTHREAD_START_ROUTINE)loadLib, remoteStr, 0, nullptr);
	if (!thread) {
		LOG_ERROR("[CRT] CreateRemoteThread failed: %u", GetLastError());
		return false;
	}

	WaitForSingleObject(thread, 5000);
	DWORD exitCode = 0;
	GetExitCodeThread(thread, &exitCode);
	CloseHandle(thread);

	if (exitCode == 0) {
		LOG_ERROR("[CRT] LoadLibrary returned NULL");
		return false;
	}

	LOG_INFO("[CRT] Success (module: 0x%X)", exitCode);
	return true;
}

// --- 방식 2: NtCreateThreadEx ---

bool Injector::InjectViaNtCreateThreadEx(HANDLE process, LPVOID remoteStr, FARPROC loadLib) {
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll) return false;

	auto NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(ntdll, "NtCreateThreadEx");
	if (!NtCreateThreadEx) {
		LOG_ERROR("[NtCTE] NtCreateThreadEx not found");
		return false;
	}

	HANDLE thread = nullptr;
	NTSTATUS status = NtCreateThreadEx(
		&thread,
		THREAD_ALL_ACCESS,
		nullptr,
		process,
		(PVOID)loadLib,
		remoteStr,
		0,       // CreateFlags: 0 = 즉시 실행
		0, 0, 0, // ZeroBits, StackSize, MaxStackSize
		nullptr  // AttributeList
	);

	if (status != 0 || !thread) {
		LOG_ERROR("[NtCTE] NtCreateThreadEx failed: NTSTATUS 0x%08X", status);
		return false;
	}

	WaitForSingleObject(thread, 5000);
	DWORD exitCode = 0;
	GetExitCodeThread(thread, &exitCode);
	CloseHandle(thread);

	if (exitCode == 0) {
		LOG_ERROR("[NtCTE] LoadLibrary returned NULL");
		return false;
	}

	LOG_INFO("[NtCTE] Success (module: 0x%X)", exitCode);
	return true;
}

// --- 방식 3: Thread Hijacking ---

bool Injector::InjectViaThreadHijack(HANDLE process, uint32_t pid, LPVOID remoteStr, bool isWow64) {
	// 타겟의 첫 번째 스레드를 찾아서 하이재킹
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot == INVALID_HANDLE_VALUE) return false;

	THREADENTRY32 te = {};
	te.dwSize = sizeof(te);
	DWORD targetTid = 0;

	if (Thread32First(snapshot, &te)) {
		do {
			if (te.th32OwnerProcessID == pid) {
				targetTid = te.th32ThreadID;
				break;
			}
		} while (Thread32Next(snapshot, &te));
	}
	CloseHandle(snapshot);

	if (targetTid == 0) {
		LOG_ERROR("[Hijack] No thread found in PID %u", pid);
		return false;
	}

	HANDLE thread = OpenThread(
		THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
		FALSE, targetTid);
	if (!thread) {
		LOG_ERROR("[Hijack] OpenThread failed for TID %u: %u", targetTid, GetLastError());
		return false;
	}

	// 스레드 일시 중지
	SuspendThread(thread);

	// 셸코드 생성 + 컨텍스트 조작
	LPVOID shellMem = nullptr;
	size_t shellSize = 0;

#ifdef _WIN64
	if (isWow64) {
		// WoW64 타겟: 32비트 컨텍스트 사용
		WOW64_CONTEXT wctx = {};
		wctx.ContextFlags = WOW64_CONTEXT_FULL;
		if (!Wow64GetThreadContext(thread, &wctx)) {
			LOG_ERROR("[Hijack] Wow64GetThreadContext failed: %u", GetLastError());
			ResumeThread(thread);
			CloseHandle(thread);
			return false;
		}

		// WoW64 프로세스의 32비트 LoadLibraryA 주소
		FARPROC loadLib = GetRemoteLoadLibraryA(process);
		if (!loadLib) {
			LOG_ERROR("[Hijack] Failed to find 32-bit LoadLibraryA");
			ResumeThread(thread);
			CloseHandle(thread);
			return false;
		}

		// 32비트 범위 검증 (WoW64 주소 공간은 4GB 이내여야 함)
		if ((uintptr_t)remoteStr > 0xFFFFFFFF || (uintptr_t)loadLib > 0xFFFFFFFF) {
			LOG_ERROR("[Hijack] WoW64: address above 4GB (remoteStr=0x%p loadLib=0x%p)", remoteStr, loadLib);
			ResumeThread(thread);
			CloseHandle(thread);
			return false;
		}

		// x86 셸코드 (32비트 WoW64 프로세스용)
		uint8_t shellcode[] = {
			0x68, 0,0,0,0,           // push remoteStr
			0xB8, 0,0,0,0,           // mov eax, loadLib
			0xFF, 0xD0,              // call eax
			0x68, 0,0,0,0,           // push originalEip
			0xC3,                    // ret
		};
		*(uint32_t*)(shellcode + 1)  = (uint32_t)(uintptr_t)remoteStr;
		*(uint32_t*)(shellcode + 6)  = (uint32_t)(uintptr_t)loadLib;
		*(uint32_t*)(shellcode + 13) = (uint32_t)wctx.Eip;

		shellSize = sizeof(shellcode);
		shellMem = VirtualAllocEx(process, nullptr, shellSize,
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!shellMem) {
			LOG_ERROR("[Hijack] VirtualAllocEx for shellcode failed: %u", GetLastError());
			ResumeThread(thread);
			CloseHandle(thread);
			return false;
		}
		WriteProcessMemory(process, shellMem, shellcode, shellSize, nullptr);
		FlushInstructionCache(process, shellMem, shellSize);

		wctx.Eip = (DWORD)(uintptr_t)shellMem;
		Wow64SetThreadContext(thread, &wctx);

	} else {
		// x64 네이티브 타겟
		CONTEXT ctx = {};
		ctx.ContextFlags = CONTEXT_FULL;
		if (!GetThreadContext(thread, &ctx)) {
			LOG_ERROR("[Hijack] GetThreadContext failed: %u", GetLastError());
			ResumeThread(thread);
			CloseHandle(thread);
			return false;
		}

		FARPROC loadLib = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");

		uint8_t shellcode[] = {
			0x48, 0x83, 0xEC, 0x28,              // sub rsp, 0x28
			0x48, 0xB9, 0,0,0,0,0,0,0,0,        // mov rcx, remoteStr
			0x48, 0xB8, 0,0,0,0,0,0,0,0,        // mov rax, loadLib
			0xFF, 0xD0,                            // call rax
			0x48, 0x83, 0xC4, 0x28,              // add rsp, 0x28
			0x48, 0xB8, 0,0,0,0,0,0,0,0,        // mov rax, originalRip
			0xFF, 0xE0,                            // jmp rax
		};
		*(uint64_t*)(shellcode + 6)  = (uint64_t)remoteStr;
		*(uint64_t*)(shellcode + 16) = (uint64_t)loadLib;
		*(uint64_t*)(shellcode + 30) = (uint64_t)ctx.Rip;

		shellSize = sizeof(shellcode);
		shellMem = VirtualAllocEx(process, nullptr, shellSize,
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!shellMem) {
			LOG_ERROR("[Hijack] VirtualAllocEx for shellcode failed: %u", GetLastError());
			ResumeThread(thread);
			CloseHandle(thread);
			return false;
		}
		WriteProcessMemory(process, shellMem, shellcode, shellSize, nullptr);
		FlushInstructionCache(process, shellMem, shellSize);

		ctx.Rip = (DWORD64)shellMem;
		SetThreadContext(thread, &ctx);
	}
#else
	// 32비트 adapter → 32비트 타겟 (WoW64 불가)
	{
		CONTEXT ctx = {};
		ctx.ContextFlags = CONTEXT_FULL;
		if (!GetThreadContext(thread, &ctx)) {
			LOG_ERROR("[Hijack] GetThreadContext failed: %u", GetLastError());
			ResumeThread(thread);
			CloseHandle(thread);
			return false;
		}

		FARPROC loadLib = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");

		uint8_t shellcode[] = {
			0x68, 0,0,0,0,           // push remoteStr
			0xB8, 0,0,0,0,           // mov eax, loadLib
			0xFF, 0xD0,              // call eax
			0x68, 0,0,0,0,           // push originalEip
			0xC3,                    // ret
		};
		*(uint32_t*)(shellcode + 1)  = (uint32_t)(uintptr_t)remoteStr;
		*(uint32_t*)(shellcode + 6)  = (uint32_t)(uintptr_t)loadLib;
		*(uint32_t*)(shellcode + 13) = (uint32_t)ctx.Eip;

		shellSize = sizeof(shellcode);
		shellMem = VirtualAllocEx(process, nullptr, shellSize,
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!shellMem) {
			LOG_ERROR("[Hijack] VirtualAllocEx for shellcode failed: %u", GetLastError());
			ResumeThread(thread);
			CloseHandle(thread);
			return false;
		}
		WriteProcessMemory(process, shellMem, shellcode, shellSize, nullptr);
		FlushInstructionCache(process, shellMem, shellSize);

		ctx.Eip = (DWORD)shellMem;
		SetThreadContext(thread, &ctx);
	}
#endif

	// 스레드 재개 — LoadLibraryA 실행 후 원래 위치로 복귀
	ResumeThread(thread);
	CloseHandle(thread);

	// LoadLibrary 완료 대기: 모듈 로드를 최대 2초간 100ms 간격으로 폴링
	{
		// remoteStr에서 DLL 경로를 읽어 파일명 추출
		char dllPathBuf[MAX_PATH] = {};
		ReadProcessMemory(process, remoteStr, dllPathBuf, sizeof(dllPathBuf) - 1, nullptr);
		const char* dllFileName = strrchr(dllPathBuf, '\\');
		dllFileName = dllFileName ? (dllFileName + 1) : dllPathBuf;

		bool found = false;
		for (int i = 0; i < 20; ++i) { // 20 * 100ms = 2초
			Sleep(100);
			HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
			if (snap == INVALID_HANDLE_VALUE) continue;
			MODULEENTRY32W me = {};
			me.dwSize = sizeof(me);
			if (Module32FirstW(snap, &me)) {
				do {
					char narrowName[MAX_PATH];
					WideCharToMultiByte(CP_ACP, 0, me.szModule, -1, narrowName, MAX_PATH, nullptr, nullptr);
					if (_stricmp(narrowName, dllFileName) == 0) {
						found = true;
						break;
					}
				} while (Module32NextW(snap, &me));
			}
			CloseHandle(snap);
			if (found) break;
		}
		if (!found) {
			LOG_WARN("[Hijack] DLL '%s' not detected in module list after 2s", dllFileName);
		}
	}

	// 셸코드 메모리 해제 (실행 완료 후)
	VirtualFreeEx(process, shellMem, 0, MEM_RELEASE);

	LOG_INFO("[Hijack] Thread %u hijacked, LoadLibrary should have executed", targetTid);
	return true;
}

// --- 방식 4: QueueUserAPC ---

bool Injector::InjectViaQueueUserAPC(HANDLE process, uint32_t pid, LPVOID remoteStr, FARPROC loadLib) {

	// 모든 스레드에 APC를 큐잉 (하나라도 alertable 상태이면 성공)
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot == INVALID_HANDLE_VALUE) return false;

	THREADENTRY32 te = {};
	te.dwSize = sizeof(te);
	int queued = 0;

	if (Thread32First(snapshot, &te)) {
		do {
			if (te.th32OwnerProcessID != pid) continue;

			HANDLE thread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
			if (!thread) continue;

			if (QueueUserAPC((PAPCFUNC)loadLib, thread, (ULONG_PTR)remoteStr)) {
				queued++;
				LOG_DEBUG("[APC] Queued to TID %u", te.th32ThreadID);
			}
			CloseHandle(thread);
		} while (Thread32Next(snapshot, &te));
	}
	CloseHandle(snapshot);

	if (queued == 0) {
		LOG_ERROR("[APC] Failed to queue APC to any thread");
		return false;
	}

	LOG_INFO("[APC] Queued LoadLibrary APC to %d thread(s)", queued);

	// APC 실행 대기: 모듈 로드를 최대 2초간 100ms 간격으로 폴링
	{
		char dllPathBuf[MAX_PATH] = {};
		ReadProcessMemory(process, remoteStr, dllPathBuf, sizeof(dllPathBuf) - 1, nullptr);
		const char* dllFileName = strrchr(dllPathBuf, '\\');
		dllFileName = dllFileName ? (dllFileName + 1) : dllPathBuf;

		bool found = false;
		for (int i = 0; i < 20; ++i) { // 20 * 100ms = 2초
			Sleep(100);
			HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
			if (snap == INVALID_HANDLE_VALUE) continue;
			MODULEENTRY32W me = {};
			me.dwSize = sizeof(me);
			if (Module32FirstW(snap, &me)) {
				do {
					char narrowName[MAX_PATH];
					WideCharToMultiByte(CP_ACP, 0, me.szModule, -1, narrowName, MAX_PATH, nullptr, nullptr);
					if (_stricmp(narrowName, dllFileName) == 0) {
						found = true;
						break;
					}
				} while (Module32NextW(snap, &me));
			}
			CloseHandle(snap);
			if (found) break;
		}
		if (found) {
			LOG_INFO("[APC] DLL '%s' loaded, freeing remote string", dllFileName);
			FreeRemoteString(process, remoteStr);
		} else {
			LOG_WARN("[APC] DLL '%s' not detected in module list after 2s, remote string not freed", dllFileName);
		}
	}

	return true;
}

// --- 메인 인젝션 함수 ---

bool Injector::InjectDll(uint32_t pid, const std::string& dllPath, InjectionMethod method) {
	EnableDebugPrivilege();

	HANDLE process = OpenProcess(
		PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
		PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
		FALSE, pid);
	if (!process) {
		LOG_ERROR("OpenProcess failed for PID %u: %u", pid, GetLastError());
		return false;
	}

	LPVOID remoteStr = AllocRemoteString(process, dllPath);
	if (!remoteStr) {
		CloseHandle(process);
		return false;
	}

	bool success = false;
	bool isWow64 = IsWow64Process(pid);

	// WoW64 프로세스면 원격 32비트 kernel32의 LoadLibraryA 주소를 찾음
	// 네이티브 프로세스면 로컬 kernel32에서 가져옴
	FARPROC loadLib = nullptr;
	if (isWow64) {
		LOG_INFO("Target is WoW64 (32-bit), resolving 32-bit LoadLibraryA...");
		loadLib = GetRemoteLoadLibraryA(process);
		if (!loadLib) {
			LOG_ERROR("Failed to resolve 32-bit LoadLibraryA for WoW64 target");
			FreeRemoteString(process, remoteStr);
			CloseHandle(process);
			return false;
		}
	} else {
		loadLib = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");
	}

	if (method == InjectionMethod::Auto) {
		// 순서대로 시도
		LOG_INFO("Auto injection: trying methods in order...");

		if (!success) {
			LOG_INFO("Trying CreateRemoteThread...");
			success = InjectViaCreateRemoteThread(process, remoteStr, loadLib);
		}
		if (!success) {
			LOG_INFO("Trying NtCreateThreadEx...");
			success = InjectViaNtCreateThreadEx(process, remoteStr, loadLib);
		}
		if (!success) {
			LOG_INFO("Trying Thread Hijacking...");
			success = InjectViaThreadHijack(process, pid, remoteStr, isWow64);
		}
		if (!success) {
			LOG_INFO("Trying QueueUserAPC...");
			success = InjectViaQueueUserAPC(process, pid, remoteStr, loadLib);
		}
	} else {
		switch (method) {
		case InjectionMethod::CreateRemoteThread:
			success = InjectViaCreateRemoteThread(process, remoteStr, loadLib);
			break;
		case InjectionMethod::NtCreateThreadEx:
			success = InjectViaNtCreateThreadEx(process, remoteStr, loadLib);
			break;
		case InjectionMethod::ThreadHijack:
			success = InjectViaThreadHijack(process, pid, remoteStr, isWow64);
			break;
		case InjectionMethod::QueueUserAPC:
			success = InjectViaQueueUserAPC(process, pid, remoteStr, loadLib);
			break;
		default:
			break;
		}
	}

	// APC 방식은 비동기이므로 remoteStr을 바로 해제하면 안 됨
	if (method != InjectionMethod::QueueUserAPC &&
		!(method == InjectionMethod::Auto && !success)) {
		// 일반 방식은 LoadLibrary 완료 후 해제
		// APC는 타이밍 이슈로 유지 (메모리 누수 감수)
	}

	if (!success) {
		FreeRemoteString(process, remoteStr);
	}
	// 성공 시에도 remoteStr은 타겟 프로세스가 사용 완료했으므로 해제 가능
	// 단, APC 방식은 비동기라 바로 해제하면 안 됨
	if (success && method != InjectionMethod::QueueUserAPC) {
		FreeRemoteString(process, remoteStr);
	}

	CloseHandle(process);
	return success;
}

LaunchResult Injector::LaunchAndInject(
	const std::string& exePath,
	const std::string& args,
	const std::string& workingDir,
	const std::string& dllPath,
	InjectionMethod method)
{
	STARTUPINFOA si = {};
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi = {};

	std::string cmdLine = "\"" + exePath + "\"";
	if (!args.empty()) cmdLine += " " + args;

	// DETACHED_PROCESS: prevent child from inheriting parent's console.
	// Without this, child's printf/cout goes to parent's stdout pipe,
	// corrupting MCP JSON-RPC transport (and potentially DAP transport).
	// If DAP needs to capture child console output in the future,
	// use STARTF_USESTDHANDLES with dedicated pipes instead of removing this flag.
	if (!CreateProcessA(
		exePath.c_str(),
		cmdLine.data(),
		nullptr, nullptr, FALSE, CREATE_SUSPENDED | DETACHED_PROCESS,
		nullptr,
		workingDir.empty() ? nullptr : workingDir.c_str(),
		&si, &pi))
	{
		LOG_ERROR("CreateProcess failed for '%s': %u", exePath.c_str(), GetLastError());
		return {};
	}

	LOG_INFO("Process created (PID: %u, TID: %u) in suspended state",
		pi.dwProcessId, pi.dwThreadId);

	if (!InjectDll(pi.dwProcessId, dllPath, method)) {
		LOG_ERROR("DLL injection failed, terminating process");
		TerminateProcess(pi.hProcess, 1);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return {};
	}

	// 메인 스레드는 항상 suspended 상태로 유지 — configurationDone 이후 resume
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return { pi.dwProcessId, pi.dwThreadId };
}

// NOTE: 현재 사용되지 않음 (의도된 설계).
// Detach 시 DLL은 타겟 프로세스에 남아있어야 재어태치가 가능하다.
// DLL 내부 PipeServer가 Detach 명령으로 디버깅 상태만 정리하고
// 파이프 서버를 유지하므로, 재연결 시 DLL 재주입이 불필요하다.
// 향후 "완전 분리" 옵션이 필요하면 이 함수를 호출하면 된다.
bool Injector::EjectDll(uint32_t pid, const std::string& dllName) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (snapshot == INVALID_HANDLE_VALUE) return false;

	MODULEENTRY32W me = {};
	me.dwSize = sizeof(me);
	HMODULE targetModule = nullptr;

	if (Module32FirstW(snapshot, &me)) {
		do {
			char narrowName[MAX_PATH];
			WideCharToMultiByte(CP_ACP, 0, me.szModule, -1, narrowName, MAX_PATH, nullptr, nullptr);
			if (_stricmp(narrowName, dllName.c_str()) == 0) {
				targetModule = me.hModule;
				break;
			}
		} while (Module32NextW(snapshot, &me));
	}
	CloseHandle(snapshot);

	if (!targetModule) return false;

	HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
		FALSE, pid);
	if (!process) return false;

	FARPROC freeLib = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "FreeLibrary");
	HANDLE thread = ::CreateRemoteThread(process, nullptr, 0,
		(LPTHREAD_START_ROUTINE)freeLib, targetModule, 0, nullptr);
	if (thread) {
		WaitForSingleObject(thread, 3000);
		CloseHandle(thread);
	}

	CloseHandle(process);
	return thread != nullptr;
}

bool Injector::IsWow64Process(uint32_t pid) {
	HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!process) return false;

	BOOL isWow64 = FALSE;
	typedef BOOL(WINAPI* IsWow64Process_t)(HANDLE, PBOOL);
	auto fn = (IsWow64Process_t)GetProcAddress(
		GetModuleHandleW(L"kernel32.dll"), "IsWow64Process");
	if (fn) fn(process, &isWow64);

	CloseHandle(process);
	return isWow64 != FALSE;
}

std::string Injector::SelectDllForTarget(uint32_t pid, const std::string& dllDir) {
	namespace fs = std::filesystem;

	if (IsWow64Process(pid)) {
		auto path32 = fs::path(dllDir) / "vcruntime_net32.dll";
		if (fs::exists(path32)) {
			LOG_INFO("Target is 32-bit (WoW64), using 32-bit payload");
			return path32.string();
		}
		LOG_WARN("32-bit DLL not found: %s", path32.string().c_str());
	}

	return (fs::path(dllDir) / "vcruntime_net.dll").string();
}

} // namespace veh
