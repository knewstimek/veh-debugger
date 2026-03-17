#include "symbol_engine.h"
#include "logger.h"
#include <algorithm>
#include <vector>

// UNICODE 빌드에서 Sym* 함수가 W 버전으로 매크로 확장되므로
// 명시적으로 W 버전과 IMAGEHLP_LINEW64를 사용한다.

namespace veh {

SymbolEngine::~SymbolEngine() {
	Cleanup();
}

bool SymbolEngine::Initialize(HANDLE hProcess) {
	std::lock_guard<std::mutex> lock(mutex_);
	if (initialized_) return true;

	hProcess_ = hProcess;

	// 심볼 옵션: undecorated 이름 + 라인 정보 + 지연 로드
	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_LOAD_LINES | SYMOPT_DEFERRED_LOADS);

	// fInvadeProcess=TRUE: 타겟 프로세스의 모든 모듈 자동 열거 + PDB 로드
	if (!SymInitialize(hProcess_, NULL, TRUE)) {
		LOG_ERROR("SymbolEngine::Initialize failed: %u", GetLastError());
		return false;
	}

	initialized_ = true;
	LOG_INFO("SymbolEngine initialized (hProcess=0x%p)", hProcess_);
	return true;
}

bool SymbolEngine::LoadModule(const std::string& imagePath, uint64_t baseAddress, uint32_t size) {
	std::lock_guard<std::mutex> lock(mutex_);
	if (!initialized_) return false;

	// char → wchar_t 변환 (UNICODE 빌드에서 SymLoadModuleExW 사용)
	int needed = MultiByteToWideChar(CP_UTF8, 0, imagePath.c_str(), -1, nullptr, 0);
	std::vector<wchar_t> wpath(needed > 0 ? needed : 1);
	MultiByteToWideChar(CP_UTF8, 0, imagePath.c_str(), -1, wpath.data(), needed);

	DWORD64 result = SymLoadModuleExW(hProcess_, NULL, wpath.data(), NULL, baseAddress, size, NULL, 0);
	if (result == 0 && GetLastError() != ERROR_SUCCESS) {
		LOG_WARN("SymbolEngine::LoadModule failed: %s (base=0x%llX err=%u)",
			imagePath.c_str(), baseAddress, GetLastError());
		return false;
	}

	LOG_INFO("SymbolEngine::LoadModule: %s at 0x%llX (size=%u)",
		imagePath.c_str(), baseAddress, size);
	return true;
}

void SymbolEngine::UnloadModule(uint64_t baseAddress) {
	std::lock_guard<std::mutex> lock(mutex_);
	if (!initialized_) return;

	SymUnloadModule64(hProcess_, baseAddress);
	LOG_INFO("SymbolEngine::UnloadModule: 0x%llX", baseAddress);
}

LineRange SymbolEngine::GetCurrentLineRange(uint64_t currentIP) {
	std::lock_guard<std::mutex> lock(mutex_);
	LineRange result;
	if (!initialized_) return result;

	// 1. 현재 IP의 소스 라인 정보 획득
	DWORD displacement = 0;
	IMAGEHLP_LINEW64 currentLine = {};
	currentLine.SizeOfStruct = sizeof(IMAGEHLP_LINEW64);

	if (!SymGetLineFromAddrW64(hProcess_, currentIP, &displacement, &currentLine)) {
		LOG_WARN("SymbolEngine: SymGetLineFromAddrW64 failed for 0x%llX: err=%u",
			currentIP, GetLastError());
		return result;
	}

	// 현재 함수의 주소 범위 확인 (nextLine이 같은 함수 내인지 검증용)
	uint8_t symBuf[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t)] = {};
	auto* symInfo = reinterpret_cast<SYMBOL_INFOW*>(symBuf);
	symInfo->SizeOfStruct = sizeof(SYMBOL_INFOW);
	symInfo->MaxNameLen = MAX_SYM_NAME;
	DWORD64 symDisp = 0;
	uint64_t funcStart = 0, funcEnd = 0;
	if (SymFromAddrW(hProcess_, currentIP, &symDisp, symInfo) && symInfo->Size > 0) {
		funcStart = symInfo->Address;
		funcEnd = symInfo->Address + symInfo->Size;
		LOG_DEBUG("SymbolEngine: func='%S' [0x%llX, 0x%llX)",
			symInfo->Name, funcStart, funcEnd);
	}

	// 현재 파일:라인 저장
	std::wstring currentFile;
	if (currentLine.FileName) {
		currentFile = currentLine.FileName;
	}
	DWORD currentLineNum = currentLine.LineNumber;
	uint64_t currentLineAddr = currentLine.Address;

	// 2. 인라인 컨텍스트 확인
	DWORD inlineContext = 0;
	DWORD frameIndex = 0;
	BOOL hasInline = SymQueryInlineTrace(
		hProcess_, currentIP, 0, currentIP, currentIP,
		&inlineContext, &frameIndex);

	if (hasInline && frameIndex > 0) {
		// 인라인 프레임 존재 — outermost context의 소스 라인 사용
		// frameIndex > 0이면 현재 IP가 인라인 확장 내부에 있음
		// outermost(호출자) context에서의 라인을 사용해야 step-over가 인라인을 건너뜀
		IMAGEHLP_LINEW64 outerLine = {};
		outerLine.SizeOfStruct = sizeof(IMAGEHLP_LINEW64);
		DWORD outerDisp = 0;

		// inlineContext + frameIndex = outermost context
		// SymGetLineFromInlineContext에 inlineContext를 전달하면
		// 해당 depth의 소스 라인을 반환
		if (SymGetLineFromInlineContextW(hProcess_, currentIP,
				inlineContext + frameIndex, 0, &outerDisp, &outerLine)) {
			if (outerLine.FileName) {
				currentFile = outerLine.FileName;
			}
			currentLineNum = outerLine.LineNumber;
			currentLineAddr = outerLine.Address;
			LOG_DEBUG("SymbolEngine: inline detected, outer=%S:%u at 0x%llX",
				currentFile.c_str(), currentLineNum, currentLineAddr);
		}
	}

	// 3. 다음 소스 라인 주소 찾기 — SymGetLineNextW64로 iterate
	IMAGEHLP_LINEW64 nextLine = currentLine;
	bool foundNext = false;
	int maxIter = 200; // 무한 루프 방지

	while (maxIter-- > 0 && SymGetLineNextW64(hProcess_, &nextLine)) {
		if (nextLine.LineNumber != currentLineNum) {
			// 함수 범위 체크: nextLine이 현재 함수 밖이면 폴백
			// (함수 끝에서 ret 시 temp BP를 건너뛰는 문제 방지)
			if (funcEnd != 0 && (nextLine.Address >= funcEnd || nextLine.Address < funcStart)) {
				LOG_INFO("SymbolEngine: nextLine 0x%llX outside func [0x%llX, 0x%llX) → fallback",
					(uint64_t)nextLine.Address, funcStart, funcEnd);
				break; // foundNext=false → 폴백 트리거
			}
			// 라인 번호가 변경됨 → 다음 라인 시작 주소
			result.success = true;
			result.startAddress = currentLineAddr;
			result.nextLineAddress = nextLine.Address;
			result.line = currentLineNum;

			// wchar → char 변환
			if (!currentFile.empty()) {
				int len = WideCharToMultiByte(CP_UTF8, 0, currentFile.c_str(), -1,
					nullptr, 0, nullptr, nullptr);
				if (len > 0) {
					result.sourceFile.resize(len - 1);
					WideCharToMultiByte(CP_UTF8, 0, currentFile.c_str(), -1,
						&result.sourceFile[0], len, nullptr, nullptr);
				}
			}

			LOG_INFO("SymbolEngine: %s:%u [0x%llX, 0x%llX)",
				result.sourceFile.c_str(), result.line,
				result.startAddress, result.nextLineAddress);
			foundNext = true;
			break;
		}
	}

	if (!foundNext) {
		// SymGetLineNext 실패 (함수 마지막 라인 등) → 폴백
		LOG_DEBUG("SymbolEngine: no next line found for %S:%u", currentFile.c_str(), currentLineNum);
	}

	return result;
}

void SymbolEngine::Cleanup() {
	std::lock_guard<std::mutex> lock(mutex_);
	if (!initialized_) return;

	SymCleanup(hProcess_);
	initialized_ = false;
	hProcess_ = nullptr;
	LOG_INFO("SymbolEngine cleaned up");
}

} // namespace veh
