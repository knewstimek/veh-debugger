#include <windows.h>
#include "veh_handler.h"
#include "pipe_server.h"
#include "breakpoint.h"
#include "hw_breakpoint.h"
#include "../common/ipc_protocol.h"
#include "../common/logger.h"

namespace {

HMODULE g_hModule = nullptr;
HANDLE g_initThread = nullptr;

// 초기화를 별도 스레드에서 수행 (DllMain loader lock 회피)
DWORD WINAPI InitThread(LPVOID) {
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

	OutputDebugStringW(L"[VEHDebugger] Init complete\n");
	return 0;
}

void Cleanup() {
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
