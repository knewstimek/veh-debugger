#pragma once
#include <cstdint>
#include "../common/ipc_protocol.h"

namespace veh {

class ValueScanner {
public:
	static ValueScanner& Instance();

	void Scan(const ValueScanRequest& request, ValueScanResponse& response,
		ValueScanEntry* entries, uint64_t excludeStart, uint64_t excludeEnd);
	void Reset();

private:
	struct SnapshotRegion {
		uint64_t base;
		uint64_t size;
		uint64_t slots;
		uint8_t* bytes;
		uint8_t* alive;
	};

	ValueScanner() = default;
	~ValueScanner() = default;
	ValueScanner(const ValueScanner&) = delete;
	ValueScanner& operator=(const ValueScanner&) = delete;

	bool First(const ValueScanRequest& request, ValueScanResponse& response,
		uint64_t excludeStart, uint64_t excludeEnd);
	bool Next(const ValueScanRequest& request, ValueScanResponse& response);
	bool Page(const ValueScanRequest& request, ValueScanResponse& response,
		ValueScanEntry* entries) const;
	bool GrowLists(uint64_t needed);
	bool AppendList(uint64_t address, uint64_t value);
	bool ConvertSnapshotToList();
	void FreeSnapshot();

	ValueScanMode mode_ = ValueScanMode::None;
	ValueScanType valueType_ = ValueScanType::None;
	uint32_t valueSize_ = 0;
	uint32_t alignment_ = 0;
	uint64_t candidateCount_ = 0;
	uint64_t listCapacity_ = 0;
	uint64_t* addresses_ = nullptr;
	uint64_t* values_ = nullptr;
	SnapshotRegion* snapshotRegions_ = nullptr;
	uint32_t snapshotRegionCount_ = 0;
};

} // namespace veh
