#include <windows.h>
#include "breakpoint.h"
#include "memory.h"
#include "../common/logger.h"
#include <cstring>

namespace veh {

BreakpointManager& BreakpointManager::Instance() {
	static BreakpointManager instance;
	return instance;
}

// INT3(0xCC) 패치로 소프트웨어 브레이크포인트 설정
uint32_t BreakpointManager::Add(uint64_t address) {
	std::lock_guard<std::mutex> lock(mutex_);

	// 이미 동일 주소에 브레이크포인트가 있는지 확인
	auto addrIt = addressToId_.find(address);
	if (addrIt != addressToId_.end()) {
		auto bpIt = breakpoints_.find(addrIt->second);
		if (bpIt != breakpoints_.end() && bpIt->second.enabled) {
			return bpIt->second.id; // 이미 설정됨
		}
	}

	// 원본 바이트 저장 후 INT3 패치
	uint8_t originalByte = 0;
	if (!PatchByte(address, 0xCC, &originalByte)) {
		return 0; // 패치 실패
	}

	uint32_t id = nextId_++;
	SoftBreakpoint bp{};
	bp.id = id;
	bp.address = address;
	bp.originalByte = originalByte;
	bp.enabled = true;

	breakpoints_[id] = bp;
	addressToId_[address] = id;

	return id;
}

// 원본 바이트 복원으로 브레이크포인트 제거
bool BreakpointManager::Remove(uint32_t id) {
	std::lock_guard<std::mutex> lock(mutex_);

	auto it = breakpoints_.find(id);
	if (it == breakpoints_.end()) {
		return false;
	}

	SoftBreakpoint& bp = it->second;

	// 활성 상태면 원본 바이트 복원
	if (bp.enabled) {
		PatchByte(bp.address, bp.originalByte);
	}

	addressToId_.erase(bp.address);
	breakpoints_.erase(it);
	return true;
}

bool BreakpointManager::RemoveByAddress(uint64_t address) {
	std::lock_guard<std::mutex> lock(mutex_);

	auto addrIt = addressToId_.find(address);
	if (addrIt == addressToId_.end()) {
		return false;
	}

	uint32_t id = addrIt->second;
	auto bpIt = breakpoints_.find(id);
	if (bpIt != breakpoints_.end() && bpIt->second.enabled) {
		PatchByte(address, bpIt->second.originalByte);
	}

	breakpoints_.erase(id);
	addressToId_.erase(addrIt);
	return true;
}

void BreakpointManager::RemoveAll() {
	std::lock_guard<std::mutex> lock(mutex_);

	for (auto& [id, bp] : breakpoints_) {
		if (bp.enabled) {
			PatchByte(bp.address, bp.originalByte);
		}
	}

	breakpoints_.clear();
	addressToId_.clear();
}

bool BreakpointManager::Enable(uint32_t id) {
	std::lock_guard<std::mutex> lock(mutex_);

	auto it = breakpoints_.find(id);
	if (it == breakpoints_.end() || it->second.enabled) {
		return false;
	}

	if (!PatchByte(it->second.address, 0xCC)) {
		return false;
	}

	it->second.enabled = true;
	return true;
}

bool BreakpointManager::Disable(uint32_t id) {
	std::lock_guard<std::mutex> lock(mutex_);

	auto it = breakpoints_.find(id);
	if (it == breakpoints_.end() || !it->second.enabled) {
		return false;
	}

	if (!PatchByte(it->second.address, it->second.originalByte)) {
		return false;
	}

	it->second.enabled = false;
	return true;
}

std::optional<SoftBreakpoint> BreakpointManager::FindByAddress(uint64_t address) {
	std::lock_guard<std::mutex> lock(mutex_);

	auto addrIt = addressToId_.find(address);
	if (addrIt == addressToId_.end()) {
		return std::nullopt;
	}

	auto bpIt = breakpoints_.find(addrIt->second);
	if (bpIt == breakpoints_.end()) {
		return std::nullopt;
	}

	return bpIt->second;
}

std::optional<SoftBreakpoint> BreakpointManager::FindById(uint32_t id) {
	std::lock_guard<std::mutex> lock(mutex_);

	auto it = breakpoints_.find(id);
	if (it == breakpoints_.end()) {
		return std::nullopt;
	}

	return it->second;
}

// 싱글스텝 완료 후 INT3 재설정
void BreakpointManager::RearmBreakpoint(uint64_t address) {
	std::lock_guard<std::mutex> lock(mutex_);

	auto addrIt = addressToId_.find(address);
	if (addrIt == addressToId_.end()) {
		return;
	}

	auto bpIt = breakpoints_.find(addrIt->second);
	if (bpIt == breakpoints_.end()) {
		return;
	}

	// INT3 다시 패치 후 enabled 복원
	PatchByte(address, 0xCC);
	bpIt->second.enabled = true;
}

// VirtualProtect로 메모리 보호 변경 후 바이트 패치
bool BreakpointManager::PatchByte(uint64_t address, uint8_t byte, uint8_t* original) {
	auto* ptr = reinterpret_cast<uint8_t*>(address);

	// 메모리 보호 변경
	DWORD oldProtect = 0;
	if (!VirtualProtect(ptr, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		return false;
	}

	// 원본 바이트 저장
	if (original) {
		*original = *ptr;
	}

	// 바이트 패치
	*ptr = byte;

	// 보호 복원
	if (!VirtualProtect(ptr, 1, oldProtect, &oldProtect)) {
		LOG_WARN("VirtualProtect restore failed at 0x%p: %lu", ptr, GetLastError());
	}

	// 명령어 캐시 플러시
	FlushInstructionCache(GetCurrentProcess(), ptr, 1);

	return true;
}

} // namespace veh
