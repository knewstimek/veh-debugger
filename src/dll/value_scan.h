#pragma once
#include <cstdint>
#include <windows.h>
#include <vector>
#include <memory>
#include <deque>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>
#include <condition_variable>
#include "../common/ipc_protocol.h"

namespace veh {

class ValueScanner {
public:
	static ValueScanner& Instance();

	void Scan(const ValueScanRequest& request, ValueScanResponse& response,
		ValueScanEntry* entries, uint64_t excludeStart, uint64_t excludeEnd);
	void Reset();
	void ScanV2(const ValueScanRequestV2& request, ValueScanResponseV2& response,
		std::vector<ValueScanEntry>& entries, uint64_t excludeStart, uint64_t excludeEnd);
	void ResetExtended();
	bool ExtendedBusy();

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

    struct Block {
        uint64_t base = 0, offset = 0;
        uint32_t span = 0, slots = 0, count = 0;
        bool dense = false;
        std::vector<uint8_t> memory;
    };
    struct Generation {
        mutable std::mutex ioMutex;
        HANDLE file = INVALID_HANDLE_VALUE;
        ValueScanType type = ValueScanType::None;
        uint32_t size = 0, alignment = 0;
        uint64_t id = 0, candidates = 0, bytes = 0;
        std::vector<Block> blocks;
        ~Generation() { if (file != INVALID_HANDLE_VALUE) CloseHandle(file); }
        bool Read(const Block& block, std::vector<uint8_t>& bytes) const;
    };
    std::mutex controlMutex_, jobMutex_;
    std::shared_ptr<Generation> current_;
    std::deque<std::shared_ptr<Generation>> history_;
    std::thread worker_;
    std::atomic<bool> cancel_{false};
    ValueScanResponseV2 job_{};
    ValueScanRequestV2 jobRequest_{};
    uint64_t jobStart_ = 0, lastEvent_ = 0;
    ValueScanPhase lastPhase_ = ValueScanPhase::Idle;
    std::function<uint64_t()> clock_ = [] { return GetTickCount64(); }; // monotonic ms; no UTC wall clock
    void ExecuteV2(ValueScanRequestV2 request, uint64_t excludeStart, uint64_t excludeEnd);
    void Progress(ValueScanPhase phase, uint64_t processed, uint64_t total,
        uint64_t matched, uint64_t bytes, bool notify, bool force = false);
    void SnapshotV2(ValueScanResponseV2& response, std::shared_ptr<Generation>* generation = nullptr);
    bool PageV2(const Generation& generation, uint64_t offset, uint32_t max,
        std::vector<ValueScanEntry>& entries);
    void StopWorker();
    void ClearLegacy();
    std::pair<uint64_t, uint64_t> RetainedBytes() const;

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
