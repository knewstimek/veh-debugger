#include <windows.h>
#include "hw_breakpoint.h"

namespace veh {
namespace {std::atomic<HwBreakpointManager*> publishedManager{nullptr};}

HwBreakpointManager& HwBreakpointManager::Instance() {
	static HwBreakpointManager instance;
    publishedManager.store(&instance,std::memory_order_release);
	return instance;
}

bool HwBreakpointManager::ApplyAtThreadEntry(CONTEXT& context,bool internal) {
    auto* manager=publishedManager.load(std::memory_order_acquire);
    if(!manager)return false;
    if(!manager->HasActive())return true;
    if(internal)manager->ClearFromContext(context);else manager->ApplyToContext(context);
    return true;
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
    Publish();

	return id;
}

bool HwBreakpointManager::Restore(const HwBreakpoint& breakpoint) {
    std::lock_guard<std::mutex> lock(mutex_);
    if(breakpoint.slot>=4||slotUsed_[breakpoint.slot])return false;
    slots_[breakpoint.slot]=breakpoint;slotUsed_[breakpoint.slot]=true;
    idToSlot_[breakpoint.id]=breakpoint.slot;Publish();return true;
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
    Publish();

	return true;
}

void HwBreakpointManager::RemoveAll() {
	std::lock_guard<std::mutex> lock(mutex_);

	for (int i = 0; i < 4; ++i) {
		slots_[i] = {};
		slotUsed_[i] = false;
	}
	idToSlot_.clear();
    Publish();
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

// Lock-free published state keeps loader callbacks away from debugger mutexes.
void HwBreakpointManager::Publish() {
    publication_.fetch_add(1,std::memory_order_acq_rel);
    CONTEXT snapshot{};
    for(uint8_t i=0;i<4;++i) {
        const bool active=slotUsed_[i]&&slots_[i].enabled;
        publishedAddress_[i].store(active?static_cast<uintptr_t>(slots_[i].address):0,std::memory_order_relaxed);
        if(active)SetDr7Bits(snapshot,i,true,slots_[i].type,slots_[i].size);
    }
    publishedDr7_.store(static_cast<uint32_t>(snapshot.Dr7),std::memory_order_release);
    publication_.fetch_add(1,std::memory_order_release);
}
void HwBreakpointManager::ApplyToContext(CONTEXT& ctx) {
    for(;;) {
        const auto before=publication_.load(std::memory_order_acquire);
        if(before&1){YieldProcessor();continue;}
        uintptr_t values[4];
        for(size_t i=0;i<4;++i)values[i]=publishedAddress_[i].load(std::memory_order_relaxed);
        const auto dr7=publishedDr7_.load(std::memory_order_acquire);
        std::atomic_thread_fence(std::memory_order_acquire);
        if(before!=publication_.load(std::memory_order_relaxed))continue;
        ctx.Dr0=values[0];ctx.Dr1=values[1];ctx.Dr2=values[2];ctx.Dr3=values[3];ctx.Dr7=dr7;
        return;
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
