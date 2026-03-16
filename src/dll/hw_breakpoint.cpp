#include <windows.h>
#include "hw_breakpoint.h"

namespace veh {

HwBreakpointManager& HwBreakpointManager::Instance() {
	static HwBreakpointManager instance;
	return instance;
}

// 빈 DR 슬롯(0~3) 찾아서 하드웨어 브레이크포인트 할당
uint32_t HwBreakpointManager::Add(uint64_t address, HwBreakType type, HwBreakSize size) {
	std::lock_guard<std::mutex> lock(mutex_);

	int slot = FindFreeSlot();
	if (slot < 0) {
		return 0; // 빈 슬롯 없음 (DR0~DR3 모두 사용 중)
	}

	uint32_t id = nextId_++;

	HwBreakpoint bp{};
	bp.id = id;
	bp.address = address;
	bp.type = type;
	bp.size = size;
	bp.slot = static_cast<uint8_t>(slot);
	bp.enabled = true;

	slots_[slot] = bp;
	slotUsed_[slot] = true;
	idToSlot_[id] = static_cast<uint8_t>(slot);

	return id;
}

// 슬롯 해제
bool HwBreakpointManager::Remove(uint32_t id) {
	std::lock_guard<std::mutex> lock(mutex_);

	auto it = idToSlot_.find(id);
	if (it == idToSlot_.end()) {
		return false;
	}

	uint8_t slot = it->second;
	slots_[slot] = {};
	slotUsed_[slot] = false;
	idToSlot_.erase(it);

	return true;
}

void HwBreakpointManager::RemoveAll() {
	std::lock_guard<std::mutex> lock(mutex_);

	for (int i = 0; i < 4; ++i) {
		slots_[i] = {};
		slotUsed_[i] = false;
	}
	idToSlot_.clear();
}

std::optional<HwBreakpoint> HwBreakpointManager::FindBySlot(uint8_t slot) {
	std::lock_guard<std::mutex> lock(mutex_);

	if (slot >= 4 || !slotUsed_[slot]) {
		return std::nullopt;
	}
	return slots_[slot];
}

std::optional<HwBreakpoint> HwBreakpointManager::FindById(uint32_t id) {
	std::lock_guard<std::mutex> lock(mutex_);

	auto it = idToSlot_.find(id);
	if (it == idToSlot_.end()) {
		return std::nullopt;
	}
	return slots_[it->second];
}

std::optional<HwBreakpoint> HwBreakpointManager::FindByAddress(uint64_t address) {
	std::lock_guard<std::mutex> lock(mutex_);

	for (int i = 0; i < 4; ++i) {
		if (slotUsed_[i] && slots_[i].address == address) {
			return slots_[i];
		}
	}
	return std::nullopt;
}

// 활성 HW 브레이크포인트를 스레드 컨텍스트에 적용
void HwBreakpointManager::ApplyToContext(CONTEXT& ctx) {
	std::lock_guard<std::mutex> lock(mutex_);

	for (int i = 0; i < 4; ++i) {
		if (slotUsed_[i] && slots_[i].enabled) {
			// DR0~DR3에 주소 설정
			switch (i) {
			case 0: ctx.Dr0 = slots_[i].address; break;
			case 1: ctx.Dr1 = slots_[i].address; break;
			case 2: ctx.Dr2 = slots_[i].address; break;
			case 3: ctx.Dr3 = slots_[i].address; break;
			}

			// DR7에 enable/type/size 비트 설정
			SetDr7Bits(ctx, static_cast<uint8_t>(i), true, slots_[i].type, slots_[i].size);
		}
	}
}

// 컨텍스트에서 모든 HW 브레이크포인트 비트 클리어
void HwBreakpointManager::ClearFromContext(CONTEXT& ctx) {
	ctx.Dr0 = 0;
	ctx.Dr1 = 0;
	ctx.Dr2 = 0;
	ctx.Dr3 = 0;
	ctx.Dr7 = 0;
}

int HwBreakpointManager::FindFreeSlot() {
	for (int i = 0; i < 4; ++i) {
		if (!slotUsed_[i]) {
			return i;
		}
	}
	return -1;
}

// DR7 비트 레이아웃:
//   [slot*2]      = local enable (1bit)
//   [16 + slot*4] = type (2bit): 00=exec, 01=write, 11=readwrite
//   [18 + slot*4] = size (2bit): 00=1byte, 01=2byte, 11=4byte, 10=8byte
void HwBreakpointManager::SetDr7Bits(CONTEXT& ctx, uint8_t slot, bool enable,
                                      HwBreakType type, HwBreakSize size) {
	auto& dr7 = ctx.Dr7;

	// local enable 비트 위치
	int enableBit = slot * 2;

	// type/size 비트 위치
	int typeBitPos = 16 + slot * 4;
	int sizeBitPos = 18 + slot * 4;

	if (enable) {
		// local enable 설정
		dr7 |= (1ULL << enableBit);

		// type 비트 클리어 후 설정
		dr7 &= ~(3ULL << typeBitPos);
		dr7 |= (static_cast<DWORD64>(type) << typeBitPos);

		// size 비트 클리어 후 설정
		dr7 &= ~(3ULL << sizeBitPos);
		dr7 |= (static_cast<DWORD64>(size) << sizeBitPos);
	} else {
		// local enable 해제
		dr7 &= ~(1ULL << enableBit);

		// type/size 비트 클리어
		dr7 &= ~(3ULL << typeBitPos);
		dr7 &= ~(3ULL << sizeBitPos);
	}
}

} // namespace veh
