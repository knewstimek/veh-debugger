#pragma once
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <mutex>
#include <windows.h>

namespace veh {

struct SoftBreakpoint {
	uint32_t id;
	uint64_t address;
	uint8_t  originalByte;
	bool     enabled;
};

class BreakpointManager {
public:
	static BreakpointManager& Instance();

	uint32_t Add(uint64_t address);
	bool Remove(uint32_t id);
	bool RemoveByAddress(uint64_t address);
	void RemoveAll();

	bool Enable(uint32_t id);
	bool Disable(uint32_t id);

	std::optional<SoftBreakpoint> FindByAddress(uint64_t address);
	std::optional<SoftBreakpoint> FindById(uint32_t id);

	// Called after single-step to re-enable breakpoint
	void RearmBreakpoint(uint64_t address);

	// ReadMemory 결과에서 활성 BP의 INT3(0xCC)를 원본 바이트로 치환.
	// 디스어셈블리 뷰 등에서 BP 유무와 관계없이 원본 명령어를 표시하기 위해 사용.
	// 실제 메모리는 변경하지 않음 — 버퍼만 수정.
	void MaskBreakpointsInBuffer(uint64_t startAddress, uint8_t* buffer, size_t size);

private:
	bool PatchByte(uint64_t address, uint8_t byte, uint8_t* original = nullptr);

	std::unordered_map<uint32_t, SoftBreakpoint> breakpoints_;
	std::unordered_map<uint64_t, uint32_t> addressToId_;
	std::mutex mutex_;
	uint32_t nextId_ = 1;
};

} // namespace veh
