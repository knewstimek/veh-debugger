#include <windows.h>
#include "stack_walk.h"
#include "veh_handler.h"
#include "threads.h"
#include "../common/logger.h"

#include <dbghelp.h>
#include <psapi.h>
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
	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_LOAD_LINES);

	// 메인 EXE 경로에서 심볼 검색 경로 구성
	char exePath[MAX_PATH] = {};
	GetModuleFileNameA(NULL, exePath, MAX_PATH);
	char exeDir[MAX_PATH] = {};
	strncpy(exeDir, exePath, MAX_PATH);
	char* lastSlash = strrchr(exeDir, '\\');
	if (lastSlash) *lastSlash = '\0';

	// 심볼 검색 경로: exe 디렉토리 + 현재 디렉토리
	char symPath[2048] = {};
	snprintf(symPath, sizeof(symPath), "%s;.", exeDir);

	if (!SymInitialize(hProcess, symPath, TRUE)) {
		LOG_ERROR("SymInitialize failed: %lu", GetLastError());
		return;
	}

	LOG_INFO("Main exe: %s", exePath);
	LOG_INFO("Symbol search path: %s", symPath);

	// 메인 EXE 심볼 로드 상태 확인
	HMODULE hExe = GetModuleHandleW(NULL);
	if (hExe) {
		IMAGEHLP_MODULE64 modInfo = {};
		modInfo.SizeOfStruct = sizeof(modInfo);
		if (SymGetModuleInfo64(hProcess, (DWORD64)hExe, &modInfo)) {
			LOG_INFO("Module symbol type: %u (1=COFF, 3=PDB, 4=Export, 7=DIA)",
				modInfo.SymType);
			LOG_INFO("Module PDB: %s", modInfo.LoadedPdbName);
		} else {
			LOG_WARN("SymGetModuleInfo64 failed for main exe: %lu", GetLastError());
		}
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
			frame.moduleBase = reinterpret_cast<uint64_t>(hModule);
			char modPath[MAX_PATH] = {};
			if (GetModuleFileNameA(hModule, modPath, MAX_PATH)) {
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

// Resolve type name recursively (handles pointers, arrays, base types)
static void ResolveTypeName(HANDLE hProcess, DWORD64 modBase, ULONG typeIndex,
                            ULONG varSize, char* out, size_t outSize, int depth = 0) {
	if (depth > 5 || outSize == 0) return;

	// 1. Try TI_GET_SYMNAME (user-defined types: struct, class, enum, typedef)
	WCHAR* symName = nullptr;
	if (SymGetTypeInfo(hProcess, modBase, typeIndex, TI_GET_SYMNAME, &symName) && symName) {
		WideCharToMultiByte(CP_UTF8, 0, symName, -1, out, (int)outSize, NULL, NULL);
		LocalFree(symName);
		if (out[0]) return;
	}

	// 2. Get the symbol tag to determine type category
	DWORD symTag = 0;
	SymGetTypeInfo(hProcess, modBase, typeIndex, TI_GET_SYMTAG, &symTag);

	// SymTagPointerType (14): resolve pointed-to type and append "*"
	if (symTag == 14) {
		DWORD pointedTypeId = 0;
		if (SymGetTypeInfo(hProcess, modBase, typeIndex, TI_GET_TYPEID, &pointedTypeId)) {
			char inner[56] = {};
			ResolveTypeName(hProcess, modBase, pointedTypeId, 0, inner, sizeof(inner), depth + 1);
			snprintf(out, outSize, "%s*", inner[0] ? inner : "void");
		} else {
			strncpy(out, "void*", outSize - 1);
		}
		return;
	}

	// SymTagArrayType (15): resolve element type and append "[]"
	if (symTag == 15) {
		DWORD elemTypeId = 0;
		if (SymGetTypeInfo(hProcess, modBase, typeIndex, TI_GET_TYPEID, &elemTypeId)) {
			char inner[48] = {};
			ResolveTypeName(hProcess, modBase, elemTypeId, 0, inner, sizeof(inner), depth + 1);
			DWORD64 arrLen = 0;
			SymGetTypeInfo(hProcess, modBase, typeIndex, TI_GET_LENGTH, &arrLen);
			DWORD64 elemLen = 0;
			SymGetTypeInfo(hProcess, modBase, elemTypeId, TI_GET_LENGTH, &elemLen);
			if (elemLen > 0) {
				snprintf(out, outSize, "%s[%llu]", inner, arrLen / elemLen);
			} else {
				snprintf(out, outSize, "%s[]", inner);
			}
		}
		return;
	}

	// SymTagBaseType (16) or fallback: use base type + size
	DWORD baseType = 0;
	if (SymGetTypeInfo(hProcess, modBase, typeIndex, TI_GET_BASETYPE, &baseType)) {
		switch (baseType) {
			case 1:  strncpy(out, "void", outSize - 1); break;
			case 2:  strncpy(out, "char", outSize - 1); break;
			case 3:  strncpy(out, "wchar_t", outSize - 1); break;
			case 6:  // btInt - distinguish by size
				if (varSize == 8) strncpy(out, "int64_t", outSize - 1);
				else if (varSize == 2) strncpy(out, "short", outSize - 1);
				else if (varSize == 1) strncpy(out, "int8_t", outSize - 1);
				else strncpy(out, "int", outSize - 1);
				break;
			case 7:  // btUInt
				if (varSize == 8) strncpy(out, "uint64_t", outSize - 1);
				else if (varSize == 2) strncpy(out, "unsigned short", outSize - 1);
				else if (varSize == 1) strncpy(out, "uint8_t", outSize - 1);
				else strncpy(out, "unsigned int", outSize - 1);
				break;
			case 8:  // btFloat - distinguish by size
				if (varSize == 8) strncpy(out, "double", outSize - 1);
				else strncpy(out, "float", outSize - 1);
				break;
			case 9:  strncpy(out, "BCD", outSize - 1); break;
			case 10: strncpy(out, "bool", outSize - 1); break;
			case 13: strncpy(out, "long", outSize - 1); break;
			case 14: strncpy(out, "unsigned long", outSize - 1); break;
			default: snprintf(out, outSize, "type(%u)", baseType); break;
		}
		return;
	}

	// Last resort: use TI_GET_LENGTH for size hint
	DWORD64 typeLen = 0;
	if (SymGetTypeInfo(hProcess, modBase, typeIndex, TI_GET_LENGTH, &typeLen)) {
		snprintf(out, outSize, "(%llu bytes)", typeLen);
	}
}

// CV register constants for x64 (from cvconst.h)
static constexpr ULONG CV_AMD64_RSP = 335;
static constexpr ULONG CV_AMD64_RBP = 334;
// x86
static constexpr ULONG CV_REG_ESP = 21;
static constexpr ULONG CV_REG_EBP = 22;

// Callback context for SymEnumSymbols
struct EnumLocalsContext {
	std::vector<LocalVariableInfo>* results;
	uint64_t frameBase;  // RBP
	uint64_t stackPtr;   // RSP
	HANDLE hProcess;
};

static BOOL CALLBACK EnumLocalsCallback(PSYMBOL_INFO pSymInfo, ULONG /*SymbolSize*/, PVOID UserContext) {
	auto* ctx = reinterpret_cast<EnumLocalsContext*>(UserContext);

	// Only interested in local variables and parameters
	if (!(pSymInfo->Flags & (SYMFLAG_LOCAL | SYMFLAG_PARAMETER | SYMFLAG_REGREL | SYMFLAG_FRAMEREL)))
		return TRUE;

	// Skip compiler-generated or empty names
	if (!pSymInfo->Name[0])
		return TRUE;

	if (ctx->results->size() >= kMaxLocals)
		return FALSE; // stop enumeration

	LocalVariableInfo var = {};
	strncpy(var.name, pSymInfo->Name, sizeof(var.name) - 1);
	var.size = pSymInfo->Size;
	var.flags = pSymInfo->Flags;

	// Resolve type name with recursive pointer/array handling
	ResolveTypeName(ctx->hProcess, pSymInfo->ModBase, pSymInfo->TypeIndex,
	                pSymInfo->Size, var.typeName, sizeof(var.typeName));

	// Compute absolute address
	if (pSymInfo->Flags & (SYMFLAG_REGREL | SYMFLAG_FRAMEREL)) {
		// Register-relative: use the correct base register
		uint64_t base = ctx->frameBase; // default: RBP
		if (pSymInfo->Register == CV_AMD64_RSP || pSymInfo->Register == CV_REG_ESP) {
			base = ctx->stackPtr; // RSP-relative
		}
		var.address = base + (int64_t)pSymInfo->Address;
	} else if (pSymInfo->Flags & SYMFLAG_REGISTER) {
		// Register-stored variable — can't read memory, skip value
		var.address = 0;
		snprintf(var.typeName, sizeof(var.typeName), "(register)");
		ctx->results->push_back(var);
		return TRUE;
	} else {
		// Static/global — use address directly
		var.address = pSymInfo->Address;
	}

	// Read value from memory (we're in the same process, just memcpy)
	if (var.address) {
		uint32_t readSize = var.size;
		if (readSize == 0) {
			// DbgHelp이 크기 정보를 제공하지 못한 경우 — 읽기 건너뜀
			ctx->results->push_back(var);
			return TRUE;
		}
		if (readSize > sizeof(var.value)) readSize = sizeof(var.value);

		__try {
			memcpy(var.value, reinterpret_cast<const void*>(var.address), readSize);
			var.valueSize = readSize;
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			var.valueSize = 0; // failed to read
		}
	}

	ctx->results->push_back(var);
	return TRUE;
}

std::vector<LocalVariableInfo> StackWalker::EnumLocals(uint32_t threadId, uint64_t instructionAddress, uint64_t frameBase) {
	std::vector<LocalVariableInfo> results;

	if (!initialized_) {
		LOG_ERROR("StackWalker not initialized");
		return results;
	}

	std::lock_guard<std::mutex> lock(dbghelpMutex_);

	HANDLE hProcess = GetCurrentProcess();

	// Set the context to the specified frame so SymEnumSymbols returns locals for that scope
	IMAGEHLP_STACK_FRAME imgFrame = {};
	imgFrame.InstructionOffset = instructionAddress;
	imgFrame.FrameOffset = frameBase;

	if (!SymSetContext(hProcess, &imgFrame, NULL)) {
		DWORD err = GetLastError();
		// ERROR_SUCCESS (0) is returned when context is already set
		if (err != ERROR_SUCCESS && err != ERROR_MOD_NOT_FOUND) {
			LOG_WARN("SymSetContext failed: %lu", err);
			return results;
		}
	}

	// Get RSP from thread context for RSP-relative variables
	uint64_t stackPtr = 0;
	CONTEXT threadCtx;
	if (VehHandler::Instance().GetStoppedContext(threadId, threadCtx)) {
#ifdef _WIN64
		stackPtr = threadCtx.Rsp;
#else
		stackPtr = threadCtx.Esp;
#endif
	}

	EnumLocalsContext ctx;
	ctx.results = &results;
	ctx.frameBase = frameBase;
	ctx.stackPtr = stackPtr;
	ctx.hProcess = hProcess;

	// Enumerate all symbols in the current scope (locals + parameters)
	if (!SymEnumSymbols(hProcess, 0, "*", EnumLocalsCallback, &ctx)) {
		LOG_WARN("SymEnumSymbols failed: %lu", GetLastError());
	}

	LOG_DEBUG("EnumLocals for frame at 0x%llX: %zu variables", instructionAddress, results.size());
	return results;
}

} // namespace veh
