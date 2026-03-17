#pragma once
#include <windows.h>
#include <dbghelp.h>
#include <string>
#include <mutex>
#include <cstdint>

namespace veh {

struct LineRange {
	bool success = false;
	uint64_t startAddress = 0;      // 현재 라인 시작 주소
	uint64_t nextLineAddress = 0;   // 다음 라인 시작 주소 (= 스텝 타겟)
	std::string sourceFile;
	uint32_t line = 0;
};

// Adapter 프로세스 내에서 독립적으로 PDB를 로드하고
// 인라인 컨텍스트 기반 소스 라인 범위를 조회하는 클래스.
// DLL의 DbgHelp 세션과는 별개 프로세스이므로 충돌 없음.
class SymbolEngine {
public:
	SymbolEngine() = default;
	~SymbolEngine();

	// targetProcess 핸들로 SymInitialize (DbgHelp 세션 키로 사용)
	bool Initialize(HANDLE hProcess);

	// 모듈 심볼 로드/언로드 (ModuleLoaded/Unloaded IPC 이벤트 시 호출)
	bool LoadModule(const std::string& imagePath, uint64_t baseAddress, uint32_t size);
	void UnloadModule(uint64_t baseAddress);

	// 현재 IP의 소스 라인 범위 조회 (인라인 컨텍스트 고려)
	// 성공 시 startAddress = 현재 라인 시작, nextLineAddress = 다음 라인 시작
	LineRange GetCurrentLineRange(uint64_t currentIP);

	void Cleanup();
	bool IsInitialized() const { return initialized_; }

private:
	HANDLE hProcess_ = nullptr;
	bool initialized_ = false;
	std::mutex mutex_;
};

} // namespace veh
