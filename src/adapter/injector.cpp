#include "injector.h"
#include "logger.h"
#include <tlhelp32.h>
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

// --- 방식 1: CreateRemoteThread ---

bool Injector::InjectViaCreateRemoteThread(HANDLE process, LPVOID remoteStr) {
	FARPROC loadLib = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");

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

bool Injector::InjectViaNtCreateThreadEx(HANDLE process, LPVOID remoteStr) {
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll) return false;

	auto NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(ntdll, "NtCreateThreadEx");
	if (!NtCreateThreadEx) {
		LOG_ERROR("[NtCTE] NtCreateThreadEx not found");
		return false;
	}

	FARPROC loadLib = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");

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

bool Injector::InjectViaThreadHijack(HANDLE process, uint32_t pid, LPVOID remoteStr) {
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

	// 컨텍스트 저장
	CONTEXT ctx = {};
	ctx.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(thread, &ctx)) {
		LOG_ERROR("[Hijack] GetThreadContext failed: %u", GetLastError());
		ResumeThread(thread);
		CloseHandle(thread);
		return false;
	}

	FARPROC loadLib = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");

	// 셸코드를 타겟에 할당
	// 셸코드: LoadLibraryA(dllPath)를 호출하고, 원래 IP로 복귀

#ifdef _WIN64
	// x64 셸코드
	// sub rsp, 0x28          ; shadow space
	// mov rcx, <remoteStr>   ; 인자 1
	// mov rax, <loadLib>     ; LoadLibraryA 주소
	// call rax
	// add rsp, 0x28
	// mov rax, <originalRip> ; 원래 RIP로 복귀
	// jmp rax
	uint8_t shellcode[] = {
		0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 0x28
		0x48, 0xB9, 0,0,0,0,0,0,0,0,                               // mov rcx, remoteStr
		0x48, 0xB8, 0,0,0,0,0,0,0,0,                               // mov rax, loadLib
		0xFF, 0xD0,                                                   // call rax
		0x48, 0x83, 0xC4, 0x28,                                     // add rsp, 0x28
		0x48, 0xB8, 0,0,0,0,0,0,0,0,                               // mov rax, originalRip
		0xFF, 0xE0,                                                   // jmp rax
	};
	*(uint64_t*)(shellcode + 6)  = (uint64_t)remoteStr;
	*(uint64_t*)(shellcode + 16) = (uint64_t)loadLib;
	*(uint64_t*)(shellcode + 30) = (uint64_t)ctx.Rip;
#else
	// x86 셸코드
	// push <remoteStr>       ; 인자 (cdecl)
	// mov eax, <loadLib>     ; LoadLibraryA 주소
	// call eax
	// push <originalEip>     ; 원래 EIP로 복귀
	// ret
	uint8_t shellcode[] = {
		0x68, 0,0,0,0,                                               // push remoteStr
		0xB8, 0,0,0,0,                                               // mov eax, loadLib
		0xFF, 0xD0,                                                   // call eax
		0x68, 0,0,0,0,                                               // push originalEip
		0xC3,                                                         // ret
	};
	*(uint32_t*)(shellcode + 1)  = (uint32_t)(uintptr_t)remoteStr;
	*(uint32_t*)(shellcode + 6)  = (uint32_t)(uintptr_t)loadLib;
	*(uint32_t*)(shellcode + 13) = (uint32_t)ctx.Eip;
#endif

	// 셸코드를 타겟에 쓰기
	LPVOID shellMem = VirtualAllocEx(process, nullptr, sizeof(shellcode),
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!shellMem) {
		LOG_ERROR("[Hijack] VirtualAllocEx for shellcode failed: %u", GetLastError());
		ResumeThread(thread);
		CloseHandle(thread);
		return false;
	}

	WriteProcessMemory(process, shellMem, shellcode, sizeof(shellcode), nullptr);
	FlushInstructionCache(process, shellMem, sizeof(shellcode));

	// IP를 셸코드로 변경
#ifdef _WIN64
	ctx.Rip = (DWORD64)shellMem;
#else
	ctx.Eip = (DWORD)shellMem;
#endif
	SetThreadContext(thread, &ctx);

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

bool Injector::InjectViaQueueUserAPC(HANDLE process, uint32_t pid, LPVOID remoteStr) {
	FARPROC loadLib = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");

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

	if (method == InjectionMethod::Auto) {
		// 순서대로 시도
		LOG_INFO("Auto injection: trying methods in order...");

		if (!success) {
			LOG_INFO("Trying CreateRemoteThread...");
			success = InjectViaCreateRemoteThread(process, remoteStr);
		}
		if (!success) {
			LOG_INFO("Trying NtCreateThreadEx...");
			success = InjectViaNtCreateThreadEx(process, remoteStr);
		}
		if (!success) {
			LOG_INFO("Trying Thread Hijacking...");
			success = InjectViaThreadHijack(process, pid, remoteStr);
		}
		if (!success) {
			LOG_INFO("Trying QueueUserAPC...");
			success = InjectViaQueueUserAPC(process, pid, remoteStr);
		}
	} else {
		switch (method) {
		case InjectionMethod::CreateRemoteThread:
			success = InjectViaCreateRemoteThread(process, remoteStr);
			break;
		case InjectionMethod::NtCreateThreadEx:
			success = InjectViaNtCreateThreadEx(process, remoteStr);
			break;
		case InjectionMethod::ThreadHijack:
			success = InjectViaThreadHijack(process, pid, remoteStr);
			break;
		case InjectionMethod::QueueUserAPC:
			success = InjectViaQueueUserAPC(process, pid, remoteStr);
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

uint32_t Injector::LaunchAndInject(
	const std::string& exePath,
	const std::string& args,
	const std::string& workingDir,
	const std::string& dllPath,
	bool stopOnEntry,
	InjectionMethod method)
{
	STARTUPINFOA si = {};
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi = {};

	std::string cmdLine = "\"" + exePath + "\"";
	if (!args.empty()) cmdLine += " " + args;

	if (!CreateProcessA(
		exePath.c_str(),
		cmdLine.data(),
		nullptr, nullptr, FALSE, CREATE_SUSPENDED,
		nullptr,
		workingDir.empty() ? nullptr : workingDir.c_str(),
		&si, &pi))
	{
		LOG_ERROR("CreateProcess failed for '%s': %u", exePath.c_str(), GetLastError());
		return 0;
	}

	LOG_INFO("Process created (PID: %u) in suspended state", pi.dwProcessId);

	if (!InjectDll(pi.dwProcessId, dllPath, method)) {
		LOG_ERROR("DLL injection failed, terminating process");
		TerminateProcess(pi.hProcess, 1);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return 0;
	}

	if (!stopOnEntry) {
		ResumeThread(pi.hThread);
	}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return pi.dwProcessId;
}

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
