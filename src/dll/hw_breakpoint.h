#pragma once
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <array>
#include <windows.h>

namespace veh {

enum class HwBreakType : uint8_t {
	Execute   = 0,
	Write     = 1,
	ReadWrite = 3,
};

enum class HwBreakSize : uint8_t {
	Byte  = 0,
	Word  = 1,
	Dword = 3,
	Qword = 2,
};

struct HwBreakpoint {
	uint32_t    id;
	uint64_t    address;
	HwBreakType type;
	HwBreakSize size;
	uint8_t     slot; // 0~3 (DR0~DR3)
	bool        enabled;
};

class HwBreakpointManager {
public:
	static HwBreakpointManager& Instance();

	// Returns breakpoint ID, or 0 on failure
	uint32_t Add(uint64_t address, HwBreakType type, HwBreakSize size);
	bool Remove(uint32_t id);
    bool Restore(const HwBreakpoint& breakpoint);
	void RemoveAll();

	std::optional<HwBreakpoint> FindBySlot(uint8_t slot);
	std::optional<HwBreakpoint> FindById(uint32_t id);
	std::optional<HwBreakpoint> FindByAddress(uint64_t address);

	// Apply HW breakpoints to a thread's context
	void ApplyToContext(CONTEXT& ctx);
	void ClearFromContext(CONTEXT& ctx);
    // Loader/exception paths read a published snapshot without taking manager locks.
    bool HasActive() const { return publishedDr7_.load(std::memory_order_acquire)!=0; }
    static bool ApplyAtThreadEntry(CONTEXT& context,bool internal);

private:
    void Publish();
    std::atomic<uint32_t> publication_{0};
    std::array<std::atomic<uintptr_t>,4> publishedAddress_{};
    std::atomic<uint32_t> publishedDr7_{0};
	int FindFreeSlot();
	void SetDr7Bits(CONTEXT& ctx, uint8_t slot, bool enable, HwBreakType type, HwBreakSize size);

	HwBreakpoint slots_[4] = {};
	bool slotUsed_[4] = {};
	std::unordered_map<uint32_t, uint8_t> idToSlot_;
	std::mutex mutex_;
	uint32_t nextId_ = 10001;  // HW BP IDs start at 10001 to avoid collision with SW BP IDs
};

} // namespace veh
