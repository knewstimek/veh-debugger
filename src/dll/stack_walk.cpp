#include <windows.h>
#include "stack_walk.h"
#include "veh_handler.h"
#include "threads.h"
#include "../common/logger.h"

#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

namespace veh {

StackWalker& StackWalker::Instance() {
	static StackWalker instance;
	return instance;
}

void StackWalker::Initialize() {
	if (initialized_) return;

	HANDLE hProcess = GetCurrentProcess();

	// 심볼 검색 옵션 설정
	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);

	if (!SymInitialize(hProcess, NULL, TRUE)) {
		LOG_ERROR("SymInitialize failed: %lu", GetLastError());
		return;
	}

	initialized_ = true;
	LOG_INFO("SymInitialize succeeded");
}

std::vector<StackFrame> StackWalker::Walk(uint32_t threadId, uint32_t startFrame, uint32_t maxFrames) {
	std::vector<StackFrame> frames;

	if (!initialized_) {
		LOG_ERROR("StackWalker not initialized");
		return frames;
	}

	std::lock_guard<std::mutex> lock(dbghelpMutex_);

	// 대상 스레드의 컨텍스트 획득
	// VEH에서 정지된 스레드면 저장된 예외 컨텍스트 사용
	CONTEXT ctx;
	if (!VehHandler::Instance().GetStoppedContext(threadId, ctx)) {
		// VEH 정지 컨텍스트가 없으면 ThreadManager에서 가져오기
		if (!ThreadManager::Instance().GetContext(threadId, ctx)) {
			LOG_ERROR("Failed to get context for thread %u", threadId);
			return frames;
		}
	}

	HANDLE hProcess = GetCurrentProcess();
	HANDLE hThread = ::OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
		FALSE, threadId);
	if (!hThread) {
		LOG_ERROR("OpenThread(%u) for stack walk failed: %lu", threadId, GetLastError());
		return frames;
	}

	// STACKFRAME64 초기화
	STACKFRAME64 sf = {};
#ifdef _WIN64
	DWORD machineType = IMAGE_FILE_MACHINE_AMD64;
	sf.AddrPC.Offset    = ctx.Rip;
	sf.AddrPC.Mode      = AddrModeFlat;
	sf.AddrFrame.Offset = ctx.Rbp;
	sf.AddrFrame.Mode   = AddrModeFlat;
	sf.AddrStack.Offset = ctx.Rsp;
	sf.AddrStack.Mode   = AddrModeFlat;
#else
	DWORD machineType = IMAGE_FILE_MACHINE_I386;
	sf.AddrPC.Offset    = ctx.Eip;
	sf.AddrPC.Mode      = AddrModeFlat;
	sf.AddrFrame.Offset = ctx.Ebp;
	sf.AddrFrame.Mode   = AddrModeFlat;
	sf.AddrStack.Offset = ctx.Esp;
	sf.AddrStack.Mode   = AddrModeFlat;
#endif

	// 심볼 이름 버퍼
	constexpr size_t kSymBufSize = sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR);
	uint8_t symBuf[kSymBufSize];
	auto* symInfo = reinterpret_cast<SYMBOL_INFO*>(symBuf);
	symInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
	symInfo->MaxNameLen = MAX_SYM_NAME;

	uint32_t frameIndex = 0;
	while (frames.size() < maxFrames) {
		BOOL ok = StackWalk64(
			machineType,
			hProcess,
			hThread,
			&sf,
			&ctx,
			NULL,                      // ReadMemoryRoutine
			SymFunctionTableAccess64,
			SymGetModuleBase64,
			NULL                       // TranslateAddress
		);

		if (!ok || sf.AddrPC.Offset == 0) break;

		// startFrame 이전의 프레임은 건너뜀
		if (frameIndex < startFrame) {
			++frameIndex;
			continue;
		}
		++frameIndex;

		StackFrame frame;
		frame.address       = sf.AddrPC.Offset;
		frame.returnAddress = sf.AddrReturn.Offset;
		frame.frameBase     = sf.AddrFrame.Offset;
		frame.line          = 0;

		// 함수명 해석
		DWORD64 displacement64 = 0;
		if (SymFromAddr(hProcess, sf.AddrPC.Offset, &displacement64, symInfo)) {
			frame.functionName = symInfo->Name;
		}

		// 줄 번호 해석
		IMAGEHLP_LINE64 lineInfo = {};
		lineInfo.SizeOfStruct = sizeof(lineInfo);
		DWORD displacement32 = 0;
		if (SymGetLineFromAddr64(hProcess, sf.AddrPC.Offset, &displacement32, &lineInfo)) {
			frame.line = lineInfo.LineNumber;
			if (lineInfo.FileName) {
				frame.sourceFile = lineInfo.FileName;
			}
		}

		// 모듈명 해석: AddrPC로 모듈 핸들 → 파일명
		HMODULE hModule = nullptr;
		if (GetModuleHandleExA(
				GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				reinterpret_cast<LPCSTR>(static_cast<uintptr_t>(sf.AddrPC.Offset)),
				&hModule)) {
			char modPath[MAX_PATH] = {};
			if (GetModuleFileNameA(hModule, modPath, MAX_PATH)) {
				// 전체 경로에서 파일명만 추출
				const char* slash = strrchr(modPath, '\\');
				frame.moduleName = slash ? (slash + 1) : modPath;
			}
		}

		frames.push_back(std::move(frame));
	}

	CloseHandle(hThread);
	LOG_DEBUG("Stack walk for thread %u: %zu frames", threadId, frames.size());
	return frames;
}

} // namespace veh
