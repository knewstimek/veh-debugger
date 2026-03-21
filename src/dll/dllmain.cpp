#include <windows.h>
#include <winternl.h>
#include <dbghelp.h>
#include "veh_handler.h"
#include "pipe_server.h"
#include "breakpoint.h"
#include "hw_breakpoint.h"
#include "stack_walk.h"
#include "../common/ipc_protocol.h"
#include "../common/logger.h"

// LdrRegisterDllNotification types (ntdll undocumented)
typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
	ULONG           Flags;
	const UNICODE_STRING* FullDllName;
	const UNICODE_STRING* BaseDllName;
	PVOID           DllBase;
	ULONG           SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
	ULONG           Flags;
	const UNICODE_STRING* FullDllName;
	const UNICODE_STRING* BaseDllName;
	PVOID           DllBase;
	ULONG           SizeOfImage;
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
	LDR_DLL_LOADED_NOTIFICATION_DATA   Loaded;
	LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

#define LDR_DLL_NOTIFICATION_REASON_LOADED   1
#define LDR_DLL_NOTIFICATION_REASON_UNLOADED 2

typedef VOID (CALLBACK *PLDR_DLL_NOTIFICATION_FUNCTION)(
	ULONG NotificationReason,
	PLDR_DLL_NOTIFICATION_DATA NotificationData,
	PVOID Context);

typedef LONG (NTAPI *pfnLdrRegisterDllNotification)(
	ULONG Flags,
	PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
	PVOID Context,
	PVOID* Cookie);

typedef LONG (NTAPI *pfnLdrUnregisterDllNotification)(PVOID Cookie);

namespace {

HMODULE g_hModule = nullptr;
HANDLE g_initThread = nullptr;
PVOID g_dllNotifCookie = nullptr;

static void CopyUnicodeToUtf8(const UNICODE_STRING* src, char* dst, size_t dstSize) {
	if (src && src->Buffer && src->Length > 0 && dstSize > 0) {
		int written = WideCharToMultiByte(CP_UTF8, 0, src->Buffer,
			(int)(src->Length / sizeof(WCHAR)),
			dst, (int)(dstSize - 1), nullptr, nullptr);
		if (written >= 0) dst[written] = '\0';
	}
}

// DLL 로드/언로드 알림 콜백
VOID CALLBACK DllNotificationCallback(
	ULONG NotificationReason,
	PLDR_DLL_NOTIFICATION_DATA NotificationData,
	PVOID Context)
{
	auto& pipe = *reinterpret_cast<veh::PipeServer*>(Context);

	veh::ModuleEvent evt{};

	if (NotificationReason == LDR_DLL_NOTIFICATION_REASON_LOADED) {
		auto& d = NotificationData->Loaded;
		evt.module.baseAddress = reinterpret_cast<uint64_t>(d.DllBase);
		evt.module.size = d.SizeOfImage;

		CopyUnicodeToUtf8(d.BaseDllName, evt.module.name, sizeof(evt.module.name));
		CopyUnicodeToUtf8(d.FullDllName, evt.module.path, sizeof(evt.module.path));

		// DbgHelp에 새 모듈 심볼 로드
		SymLoadModuleEx(GetCurrentProcess(), nullptr,
			evt.module.path, evt.module.name,
			(DWORD64)d.DllBase, d.SizeOfImage, nullptr, 0);

		pipe.SendEvent(static_cast<uint32_t>(veh::IpcEvent::ModuleLoaded),
		               &evt, sizeof(evt));
		LOG_DEBUG("Module loaded: %s (0x%llX)", evt.module.name, evt.module.baseAddress);

	} else if (NotificationReason == LDR_DLL_NOTIFICATION_REASON_UNLOADED) {
		auto& d = NotificationData->Unloaded;
		evt.module.baseAddress = reinterpret_cast<uint64_t>(d.DllBase);
		evt.module.size = d.SizeOfImage;

		CopyUnicodeToUtf8(d.BaseDllName, evt.module.name, sizeof(evt.module.name));
		CopyUnicodeToUtf8(d.FullDllName, evt.module.path, sizeof(evt.module.path));

		// DbgHelp에서 모듈 심볼 제거
		SymUnloadModule64(GetCurrentProcess(), (DWORD64)d.DllBase);

		pipe.SendEvent(static_cast<uint32_t>(veh::IpcEvent::ModuleUnloaded),
		               &evt, sizeof(evt));
		LOG_DEBUG("Module unloaded: %s (0x%llX)", evt.module.name, evt.module.baseAddress);
	}
}

// 시스템 디렉토리에서 dbghelp.dll 강제 로드 (delay-loaded)
// 타겟 폴더에 구버전 dbghelp.dll이 있어도 시스템 것을 사용
static void PreloadSystemDbgHelp() {
	HMODULE h = LoadLibraryExA("dbghelp.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (!h) {
		// 폴백: 시스템 디렉토리 경로 직접 구성
		char sysDir[MAX_PATH];
		UINT len = GetSystemDirectoryA(sysDir, MAX_PATH);
		if (len > 0 && len < MAX_PATH - 16) {
			strcat_s(sysDir, "\\dbghelp.dll");
			h = LoadLibraryA(sysDir);
		}
	}
	if (h) {
		OutputDebugStringW(L"[VEHDebugger] System dbghelp.dll pre-loaded\n");
	} else {
		OutputDebugStringW(L"[VEHDebugger] WARNING: Failed to pre-load system dbghelp.dll\n");
	}
	// h를 FreeLibrary하지 않음 -- delay-load가 이미 로드된 모듈을 사용
}

// 초기화를 별도 스레드에서 수행 (DllMain loader lock 회피)
DWORD WINAPI InitThread(LPVOID) {
	// 시스템 dbghelp.dll 선로드 (타겟 폴더의 구버전 방지)
	PreloadSystemDbgHelp();

	// DLL 로그를 파일로 출력 (디버깅용)
	char logPath[MAX_PATH];
	snprintf(logPath, sizeof(logPath), "veh_dll_%u.log", GetCurrentProcessId());
	veh::Logger::Instance().SetFile(logPath);
	veh::Logger::Instance().SetLevel(veh::LogLevel::Debug);

	// 파이프 서버 시작
	uint32_t pid = GetCurrentProcessId();
	auto& pipe = veh::PipeServer::Instance();
	if (!pipe.Start(pid)) {
		OutputDebugStringW(L"[VEHDebugger] Pipe server start failed\n");
		return 1;
	}

	// 디버그 이벤트 콜백 설정 (VEH 설치 전에 설정하여 레이스 방지)
	auto& veh = veh::VehHandler::Instance();
	veh.SetEventCallback([&pipe](const veh::DebugEvent& event) {
		switch (event.type) {
		case veh::DebugEventType::BreakpointHit: {
			veh::BreakpointHitEvent payload{};
			payload.threadId = event.threadId;
			payload.breakpointId = event.breakpointId;
			payload.address = event.address;
			// VEH 정지 시점의 레지스터를 이벤트에 포함 (어댑터 측 조건부 BP 평가용)
			memset(&payload.regs, 0, sizeof(payload.regs));
			if (event.context) {
				const CONTEXT& ctx = *event.context;
#ifdef _WIN64
				payload.regs.is32bit = 0;
				payload.regs.rax = ctx.Rax; payload.regs.rbx = ctx.Rbx;
				payload.regs.rcx = ctx.Rcx; payload.regs.rdx = ctx.Rdx;
				payload.regs.rsi = ctx.Rsi; payload.regs.rdi = ctx.Rdi;
				payload.regs.rbp = ctx.Rbp; payload.regs.rsp = ctx.Rsp;
				payload.regs.r8  = ctx.R8;  payload.regs.r9  = ctx.R9;
				payload.regs.r10 = ctx.R10; payload.regs.r11 = ctx.R11;
				payload.regs.r12 = ctx.R12; payload.regs.r13 = ctx.R13;
				payload.regs.r14 = ctx.R14; payload.regs.r15 = ctx.R15;
				payload.regs.rip = ctx.Rip;
				payload.regs.rflags = ctx.EFlags;
				payload.regs.cs = ctx.SegCs; payload.regs.ss = ctx.SegSs;
				payload.regs.ds = ctx.SegDs; payload.regs.es = ctx.SegEs;
				payload.regs.fs = ctx.SegFs; payload.regs.gs = ctx.SegGs;
				payload.regs.dr0 = ctx.Dr0; payload.regs.dr1 = ctx.Dr1;
				payload.regs.dr2 = ctx.Dr2; payload.regs.dr3 = ctx.Dr3;
				payload.regs.dr6 = ctx.Dr6; payload.regs.dr7 = ctx.Dr7;
				memcpy(payload.regs.xmm, ctx.FltSave.XmmRegisters, sizeof(payload.regs.xmm));
#else
				payload.regs.is32bit = 1;
				payload.regs.rax = ctx.Eax; payload.regs.rbx = ctx.Ebx;
				payload.regs.rcx = ctx.Ecx; payload.regs.rdx = ctx.Edx;
				payload.regs.rsi = ctx.Esi; payload.regs.rdi = ctx.Edi;
				payload.regs.rbp = ctx.Ebp; payload.regs.rsp = ctx.Esp;
				payload.regs.rip = ctx.Eip;
				payload.regs.rflags = ctx.EFlags;
				payload.regs.cs = ctx.SegCs; payload.regs.ss = ctx.SegSs;
				payload.regs.ds = ctx.SegDs; payload.regs.es = ctx.SegEs;
				payload.regs.fs = ctx.SegFs; payload.regs.gs = ctx.SegGs;
				payload.regs.dr0 = ctx.Dr0; payload.regs.dr1 = ctx.Dr1;
				payload.regs.dr2 = ctx.Dr2; payload.regs.dr3 = ctx.Dr3;
				payload.regs.dr6 = ctx.Dr6; payload.regs.dr7 = ctx.Dr7;
#endif
			}
			pipe.SendEvent(static_cast<uint32_t>(veh::IpcEvent::BreakpointHit),
			               &payload, sizeof(payload));
			break;
		}
		case veh::DebugEventType::SingleStepComplete: {
			veh::StepCompletedEvent payload{};
			payload.threadId = event.threadId;
			payload.address = event.address;
			pipe.SendEvent(static_cast<uint32_t>(veh::IpcEvent::StepCompleted),
			               &payload, sizeof(payload));
			break;
		}
		case veh::DebugEventType::Exception: {
			veh::ExceptionEvent payload{};
			payload.threadId = event.threadId;
			payload.exceptionCode = event.exceptionCode;
			payload.address = event.address;
			pipe.SendEvent(static_cast<uint32_t>(veh::IpcEvent::ExceptionOccurred),
			               &payload, sizeof(payload));
			break;
		}
		default:
			break;
		}
	});

	// VEH 핸들러 설치 (콜백 설정 후에 설치하여 레이스 방지)
	if (!veh.Install()) {
		OutputDebugStringW(L"[VEHDebugger] VEH handler install failed\n");
		pipe.Stop();
		return 1;
	}

	// 모듈 로드/언로드 알림 등록 (LdrRegisterDllNotification)
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (hNtdll) {
		auto pRegister = reinterpret_cast<pfnLdrRegisterDllNotification>(
			GetProcAddress(hNtdll, "LdrRegisterDllNotification"));
		if (pRegister) {
			LONG status = pRegister(0, DllNotificationCallback, &pipe, &g_dllNotifCookie);
			if (status == 0) {
				LOG_INFO("LdrRegisterDllNotification succeeded");
			} else {
				LOG_WARN("LdrRegisterDllNotification failed: 0x%08X", status);
			}
		} else {
			LOG_WARN("LdrRegisterDllNotification not found in ntdll");
		}
	}

	OutputDebugStringW(L"[VEHDebugger] Init complete\n");
	return 0;
}

void Cleanup() {
	// 모듈 알림 해제
	if (g_dllNotifCookie) {
		HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
		if (hNtdll) {
			auto pUnregister = reinterpret_cast<pfnLdrUnregisterDllNotification>(
				GetProcAddress(hNtdll, "LdrUnregisterDllNotification"));
			if (pUnregister) pUnregister(g_dllNotifCookie);
		}
		g_dllNotifCookie = nullptr;
	}

	if (g_initThread) {
		WaitForSingleObject(g_initThread, 3000);
		CloseHandle(g_initThread);
		g_initThread = nullptr;
	}
	veh::BreakpointManager::Instance().RemoveAll();
	veh::HwBreakpointManager::Instance().RemoveAll();
	veh::PipeServer::Instance().Stop();
	veh::VehHandler::Instance().Uninstall();
	OutputDebugStringW(L"[VEHDebugger] Cleanup complete\n");
}

} // anonymous namespace

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
	switch (reason) {
	case DLL_PROCESS_ATTACH:
		g_hModule = hModule;
		DisableThreadLibraryCalls(hModule);
		// loader lock 회피: 별도 스레드에서 초기화
		g_initThread = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
		if (!g_initThread) {
			LOG_ERROR("CreateThread for InitThread failed: %lu", GetLastError());
			return FALSE;
		}
		break;

	case DLL_PROCESS_DETACH:
		Cleanup();
		break;
	}

	return TRUE;
}
