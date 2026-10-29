#include "value_scan.h"
#include "memory.h"
#include "breakpoint.h"
#include "pipe_server.h"
#include "threads.h"
#include "veh_handler.h"
#include <stdexcept>
#include <windows.h>
#include <algorithm>
#include <cstring>
#include <limits>
#include <type_traits>

namespace veh {

namespace {

constexpr uint64_t kListCap = 16ull * 1024 * 1024;
constexpr uint64_t kSnapshotCap = 512ull * 1024 * 1024;
constexpr size_t kChunkSize = 64 * 1024;

struct ScanRegion {
	uint64_t start;
	uint64_t end;
	uint64_t first;
	uint64_t slots;
};

uint32_t ValueSize(ValueScanType type) {
	switch (type) {
	case ValueScanType::I8:
	case ValueScanType::U8: return 1;
	case ValueScanType::I16:
	case ValueScanType::U16: return 2;
	case ValueScanType::I32:
	case ValueScanType::U32:
	case ValueScanType::F32: return 4;
	case ValueScanType::I64:
	case ValueScanType::U64:
	case ValueScanType::F64: return 8;
	default: return 0;
	}
}

void UserSpaceBounds(uint64_t start, uint64_t end, uint64_t& lo, uint64_t& hi) {
	SYSTEM_INFO si{};
	GetSystemInfo(&si);
	const uint64_t minApp = reinterpret_cast<uint64_t>(si.lpMinimumApplicationAddress);
	const uint64_t maxApp = reinterpret_cast<uint64_t>(si.lpMaximumApplicationAddress) + 1;
	lo = start > minApp ? start : minApp;
	hi = (end == 0 || end > maxApp) ? maxApp : end;
}

bool IsReadable(DWORD protect) {
	return (protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0 && (protect & 0xFF) != 0;
}

bool MatchesFilter(RegionFilter filter, bool value) {
	return filter == RegionFilter::Any || (filter == RegionFilter::Require) == value;
}

uint8_t RegionTypeBit(DWORD type) {
	switch (type) {
	case MEM_IMAGE: return kRegionTypeImage;
	case MEM_MAPPED: return kRegionTypeMapped;
	default: return kRegionTypePrivate;
	}
}

bool IsEligible(const ValueScanRequest& request, const MEMORY_BASIC_INFORMATION& mbi) {
	return mbi.State == MEM_COMMIT && IsReadable(mbi.Protect)
		&& MatchesFilter(request.writable, (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY
			| PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0)
		&& MatchesFilter(request.executable, (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ
			| PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0)
		&& (request.typeMask == 0 || (request.typeMask & RegionTypeBit(mbi.Type)) != 0);
}

uint64_t AlignUp(uint64_t value, uint32_t alignment) {
	const uint64_t rem = value % alignment;
	if (!rem) return value;
	const uint64_t add = alignment - rem;
	return value > (std::numeric_limits<uint64_t>::max)() - add ? 0 : value + add;
}

bool Overlaps(uint64_t address, uint32_t size, uint64_t start, uint64_t end) {
	return start < end && address < end && address + size > start;
}

uint64_t LoadRaw(const uint8_t* bytes, uint32_t size) {
	uint64_t value = 0;
	memcpy(&value, bytes, size);
	return value;
}

template <typename T>
T RawAs(uint64_t raw) {
	T value{};
	memcpy(&value, &raw, sizeof(value));
	return value;
}

template <typename T>
bool MatchValue(T current, T previous, T value, T value2, ValueScanCompare compare) {
	switch (compare) {
	case ValueScanCompare::Exact: return current == value;
	case ValueScanCompare::Between: return current >= value && current <= value2;
	case ValueScanCompare::Greater: return current > value;
	case ValueScanCompare::Less: return current < value;
	case ValueScanCompare::Unknown: return true;
	case ValueScanCompare::Changed: return current != previous;
	case ValueScanCompare::Unchanged: return current == previous;
	case ValueScanCompare::Increased: return current > previous;
	case ValueScanCompare::Decreased: return current < previous;
	case ValueScanCompare::IncreasedBy: return current == previous + value;
	case ValueScanCompare::DecreasedBy: return current == previous - value;
	default: return false;
	}
}

template <typename T>
bool MatchUnsigned(T current, T previous, T value, T value2, ValueScanCompare compare) {
	if (compare == ValueScanCompare::IncreasedBy)
		return current >= previous && static_cast<T>(current - previous) == value;
	if (compare == ValueScanCompare::DecreasedBy)
		return previous >= current && static_cast<T>(previous - current) == value;
	return MatchValue(current, previous, value, value2, compare);
}

template <typename T>
bool MatchSigned(T current, T previous, T value, T value2, ValueScanCompare compare) {
	using U = typename std::make_unsigned<T>::type;
	if (compare == ValueScanCompare::IncreasedBy) {
		if (value < 0 || current < previous) return false;
		return static_cast<U>(current) - static_cast<U>(previous) == static_cast<U>(value);
	}
	if (compare == ValueScanCompare::DecreasedBy) {
		if (value < 0 || current > previous) return false;
		return static_cast<U>(previous) - static_cast<U>(current) == static_cast<U>(value);
	}
	return MatchValue(current, previous, value, value2, compare);
}

bool Matches(ValueScanType type, uint64_t current, uint64_t previous,
	uint64_t value, uint64_t value2, ValueScanCompare compare) {
	switch (type) {
	case ValueScanType::I8: return MatchSigned(RawAs<int8_t>(current), RawAs<int8_t>(previous),
		RawAs<int8_t>(value), RawAs<int8_t>(value2), compare);
	case ValueScanType::U8: return MatchUnsigned(RawAs<uint8_t>(current), RawAs<uint8_t>(previous),
		RawAs<uint8_t>(value), RawAs<uint8_t>(value2), compare);
	case ValueScanType::I16: return MatchSigned(RawAs<int16_t>(current), RawAs<int16_t>(previous),
		RawAs<int16_t>(value), RawAs<int16_t>(value2), compare);
	case ValueScanType::U16: return MatchUnsigned(RawAs<uint16_t>(current), RawAs<uint16_t>(previous),
		RawAs<uint16_t>(value), RawAs<uint16_t>(value2), compare);
	case ValueScanType::I32: return MatchSigned(RawAs<int32_t>(current), RawAs<int32_t>(previous),
		RawAs<int32_t>(value), RawAs<int32_t>(value2), compare);
	case ValueScanType::U32: return MatchUnsigned(RawAs<uint32_t>(current), RawAs<uint32_t>(previous),
		RawAs<uint32_t>(value), RawAs<uint32_t>(value2), compare);
	case ValueScanType::I64: return MatchSigned(RawAs<int64_t>(current), RawAs<int64_t>(previous),
		RawAs<int64_t>(value), RawAs<int64_t>(value2), compare);
	case ValueScanType::U64: return MatchUnsigned(current, previous, value, value2, compare);
	case ValueScanType::F32: return MatchValue(RawAs<float>(current), RawAs<float>(previous),
		RawAs<float>(value), RawAs<float>(value2), compare);
	case ValueScanType::F64: return MatchValue(RawAs<double>(current), RawAs<double>(previous),
		RawAs<double>(value), RawAs<double>(value2), compare);
	default: return false;
	}
}

bool BitSet(const uint8_t* bits, uint64_t index) {
	return (bits[index >> 3] & static_cast<uint8_t>(1u << (index & 7))) != 0;
}

void SetBit(uint8_t* bits, uint64_t index) {
	bits[index >> 3] |= static_cast<uint8_t>(1u << (index & 7));
}

void ClearBit(uint8_t* bits, uint64_t index) {
	bits[index >> 3] &= static_cast<uint8_t>(~(1u << (index & 7)));
}

uint64_t RegionSlotCount(uint64_t start, uint64_t end, uint32_t size, uint32_t alignment,
	uint64_t& first) {
	first = AlignUp(start, alignment);
	if (!first || first >= end || end - first < size) return 0;
	return 1 + (end - first - size) / alignment;
}

bool DiscoverRegions(const ValueScanRequest& request, uint32_t valueSize,
	ScanRegion*& regions, uint32_t& regionCount, uint64_t& snapshotBytes,
        uint64_t cap = kSnapshotCap, const std::atomic<bool>* cancelled = nullptr,
        const std::function<void(uint64_t)>& progress = {}, uint64_t regionBudget = UINT64_MAX) {
	regions = nullptr;
	regionCount = 0;
	snapshotBytes = 0;
	uint64_t lo, hi;
	UserSpaceBounds(request.startAddress, request.endAddress, lo, hi);

	uint32_t count = 0;
	for (uint64_t addr = lo; addr < hi;) {
		if (cancelled && cancelled->load()) return false;
		if (progress) progress(addr - lo);
		MEMORY_BASIC_INFORMATION mbi{};
		if (!VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) break;
		const uint64_t base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
		const uint64_t next = base + mbi.RegionSize;
		if (next <= addr) break;
		const uint64_t start = addr > base ? addr : base;
		const uint64_t end = next < hi ? next : hi;
		uint64_t first = 0;
		const uint64_t slots = IsEligible(request, mbi)
			? RegionSlotCount(start, end, valueSize, request.alignment, first) : 0;
		if (slots) {
			if (count == (std::numeric_limits<uint32_t>::max)()) return false;
			++count;
			if (request.compare == ValueScanCompare::Unknown) {
				const uint64_t bytes = end - first;
				const uint64_t bitmap = (slots + 7) / 8;
				if (snapshotBytes > cap || bytes > cap - snapshotBytes
					|| bitmap > cap - snapshotBytes - bytes) {
					snapshotBytes = cap == UINT64_MAX ? cap : cap + 1;
				}
				else snapshotBytes += bytes + bitmap;
			}
		}
		addr = next;
	}

	if (!count) return true;
	if(uint64_t(count)*sizeof(ScanRegion)>regionBudget) {snapshotBytes=UINT64_MAX;return false;}
	regions = static_cast<ScanRegion*>(VirtualAlloc(nullptr, static_cast<SIZE_T>(count) * sizeof(ScanRegion),
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!regions) return false;
	const void* regionAllocation = regions;
	uint32_t filled = 0;
	for (uint64_t addr = lo; addr < hi && filled < count;) {
		if (cancelled && cancelled->load()) return false;
		if (progress) progress(addr - lo);
		MEMORY_BASIC_INFORMATION mbi{};
		if (!VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) break;
		const uint64_t base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
		const uint64_t next = base + mbi.RegionSize;
		if (next <= addr) break;
		const uint64_t start = addr > base ? addr : base;
		const uint64_t end = next < hi ? next : hi;
		uint64_t first = 0;
		const uint64_t slots = mbi.AllocationBase != regionAllocation && IsEligible(request, mbi)
			? RegionSlotCount(start, end, valueSize, request.alignment, first) : 0;
		if (slots) regions[filled++] = {start, end, first, slots};
		addr = next;
	}
	regionCount = filled;
	if (request.compare == ValueScanCompare::Unknown) {
		snapshotBytes = 0;
		for (uint32_t i = 0; i < filled; ++i) {
			const uint64_t bytes = regions[i].end - regions[i].first;
			const uint64_t bitmap = (regions[i].slots + 7) / 8;
			if (snapshotBytes > cap || bytes > cap - snapshotBytes
				|| bitmap > cap - snapshotBytes - bytes) {
				snapshotBytes = cap == UINT64_MAX ? cap : cap + 1;
				break;
			}
			snapshotBytes += bytes + bitmap;
		}
	}
	return true;
}

} // namespace

ValueScanner& ValueScanner::Instance() {
	static ValueScanner instance;
	return instance;
}

void ValueScanner::FreeSnapshot() {
	if (snapshotRegions_) {
		for (uint32_t i = 0; i < snapshotRegionCount_; ++i) {
			if (snapshotRegions_[i].bytes) VirtualFree(snapshotRegions_[i].bytes, 0, MEM_RELEASE);
			if (snapshotRegions_[i].alive) VirtualFree(snapshotRegions_[i].alive, 0, MEM_RELEASE);
		}
		VirtualFree(snapshotRegions_, 0, MEM_RELEASE);
	}
	snapshotRegions_ = nullptr;
	snapshotRegionCount_ = 0;
}

void ValueScanner::Reset() {
	ResetExtended();
	ClearLegacy();
}

void ValueScanner::ClearLegacy() {
	if (addresses_) VirtualFree(addresses_, 0, MEM_RELEASE);
	if (values_) VirtualFree(values_, 0, MEM_RELEASE);
	addresses_ = nullptr;
	values_ = nullptr;
	listCapacity_ = 0;
	FreeSnapshot();
	mode_ = ValueScanMode::None;
	valueType_ = ValueScanType::None;
	valueSize_ = 0;
	alignment_ = 0;
	candidateCount_ = 0;
}

bool ValueScanner::GrowLists(uint64_t needed) {
	if (needed <= listCapacity_) return true;
	if (needed > kListCap) return false;
	uint64_t capacity = listCapacity_ ? listCapacity_ * 2 : 4096;
	if (capacity < needed) capacity = needed;
	if (capacity > kListCap) capacity = kListCap;
	const SIZE_T bytes = static_cast<SIZE_T>(capacity * sizeof(uint64_t));
	auto* addresses = static_cast<uint64_t*>(VirtualAlloc(nullptr, bytes,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!addresses) return false;
	auto* values = static_cast<uint64_t*>(VirtualAlloc(nullptr, bytes,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!values) {
		VirtualFree(addresses, 0, MEM_RELEASE);
		return false;
	}
	if (candidateCount_) {
		memcpy(addresses, addresses_, static_cast<size_t>(candidateCount_) * sizeof(uint64_t));
		memcpy(values, values_, static_cast<size_t>(candidateCount_) * sizeof(uint64_t));
	}
	if (addresses_) VirtualFree(addresses_, 0, MEM_RELEASE);
	if (values_) VirtualFree(values_, 0, MEM_RELEASE);
	addresses_ = addresses;
	values_ = values;
	listCapacity_ = capacity;
	return true;
}

bool ValueScanner::AppendList(uint64_t address, uint64_t value) {
	if (candidateCount_ >= kListCap || !GrowLists(candidateCount_ + 1)) return false;
	addresses_[candidateCount_] = address;
	values_[candidateCount_] = value;
	++candidateCount_;
	return true;
}

bool ValueScanner::First(const ValueScanRequest& request, ValueScanResponse& response,
	uint64_t excludeStart, uint64_t excludeEnd) {
	Reset();
	valueSize_ = ValueSize(request.valueType);
	if (!valueSize_ || request.alignment == 0 || request.alignment > 4096
		|| request.compare > ValueScanCompare::Unknown) {
		response.failure = ValueScanFailure::InvalidRequest;
		return false;
	}
	valueType_ = request.valueType;
	alignment_ = request.alignment;

	ScanRegion* regions = nullptr;
	uint32_t regionCount = 0;
	uint64_t snapshotBytes = 0;
	if (!DiscoverRegions(request, valueSize_, regions, regionCount, snapshotBytes)) {
		response.failure = ValueScanFailure::AllocationFailed;
		Reset();
		return false;
	}
	const uint64_t snapshotMetadata = static_cast<uint64_t>(regionCount) * sizeof(SnapshotRegion);
	if (request.compare == ValueScanCompare::Unknown
		&& (snapshotBytes > kSnapshotCap || snapshotMetadata > kSnapshotCap - snapshotBytes)) {
		if (regions) VirtualFree(regions, 0, MEM_RELEASE);
		response.failure = ValueScanFailure::SnapshotTooLarge;
		Reset();
		return false;
	}

	auto* scratch = static_cast<uint8_t*>(VirtualAlloc(nullptr, kChunkSize,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!scratch) {
		if (regions) VirtualFree(regions, 0, MEM_RELEASE);
		response.failure = ValueScanFailure::AllocationFailed;
		Reset();
		return false;
	}

	bool ok = true;
	if (request.compare == ValueScanCompare::Unknown) {
		mode_ = ValueScanMode::Snapshot;
		if (regionCount) {
			snapshotRegions_ = static_cast<SnapshotRegion*>(VirtualAlloc(nullptr,
				static_cast<SIZE_T>(regionCount) * sizeof(SnapshotRegion),
				MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
			if (!snapshotRegions_) ok = false;
		}
		if (ok) snapshotRegionCount_ = regionCount;
		for (uint32_t i = 0; ok && i < regionCount; ++i) {
			auto& source = regions[i];
			auto& target = snapshotRegions_[i];
			target = {};
			target.base = source.first;
			target.size = source.end - source.first;
			target.slots = source.slots;
			target.bytes = static_cast<uint8_t*>(VirtualAlloc(nullptr, static_cast<SIZE_T>(target.size),
				MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
			target.alive = static_cast<uint8_t*>(VirtualAlloc(nullptr, static_cast<SIZE_T>((target.slots + 7) / 8),
				MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
			if (!target.bytes || !target.alive) { ok = false; break; }

			uint64_t slot = 0;
			while (slot < target.slots) {
				const uint64_t address = target.base + slot * alignment_;
				const uint64_t remaining = target.size - (address - target.base);
				const size_t len = static_cast<size_t>(remaining < kChunkSize ? remaining : kChunkSize);
				const uint64_t slotsInChunk = len < valueSize_ ? 0 : 1 + (len - valueSize_) / alignment_;
				if (!slotsInChunk) break;
				if (SafeCopyMemory(scratch, reinterpret_cast<const void*>(address), len)) {
					BreakpointManager::Instance().MaskBreakpointsInBuffer(address, scratch, len);
					memcpy(target.bytes + (address - target.base), scratch, len);
					response.scannedBytes += len;
					for (uint64_t j = 0; j < slotsInChunk; ++j) {
						const uint64_t candidate = address + j * alignment_;
						if (!Overlaps(candidate, valueSize_, excludeStart, excludeEnd)) {
							SetBit(target.alive, slot + j);
							++candidateCount_;
						}
					}
				}
				slot += slotsInChunk;
			}
		}
	} else {
		mode_ = ValueScanMode::List;
		for (uint32_t i = 0; ok && i < regionCount; ++i) {
			const auto& region = regions[i];
			uint64_t slot = 0;
			while (slot < region.slots) {
				const uint64_t address = region.first + slot * alignment_;
				const uint64_t remaining = region.end - address;
				const size_t len = static_cast<size_t>(remaining < kChunkSize ? remaining : kChunkSize);
				const uint64_t slotsInChunk = len < valueSize_ ? 0 : 1 + (len - valueSize_) / alignment_;
				if (!slotsInChunk) break;
				if (SafeCopyMemory(scratch, reinterpret_cast<const void*>(address), len)) {
					BreakpointManager::Instance().MaskBreakpointsInBuffer(address, scratch, len);
					response.scannedBytes += len;
					for (uint64_t j = 0; j < slotsInChunk; ++j) {
						const uint64_t candidate = address + j * alignment_;
						const uint64_t raw = LoadRaw(scratch + j * alignment_, valueSize_);
						if (!Overlaps(candidate, valueSize_, excludeStart, excludeEnd)
							&& Matches(valueType_, raw, 0, request.value, request.value2, request.compare)) {
							if (candidateCount_ >= kListCap) {
								response.failure = ValueScanFailure::TooManyResults;
								ok = false;
								break;
							}
							if (!AppendList(candidate, raw)) {
								response.failure = ValueScanFailure::AllocationFailed;
								ok = false;
								break;
							}
						}
					}
				}
				slot += slotsInChunk;
			}
		}
	}

	VirtualFree(scratch, 0, MEM_RELEASE);
	if (regions) VirtualFree(regions, 0, MEM_RELEASE);
	if (!ok) {
		if (response.failure == ValueScanFailure::None)
			response.failure = ValueScanFailure::AllocationFailed;
		Reset();
		return false;
	}
	return true;
}

bool ValueScanner::ConvertSnapshotToList() {
	if (candidateCount_ > kListCap) return true;
	if (!candidateCount_) {
		FreeSnapshot();
		mode_ = ValueScanMode::List;
		return true;
	}
	const SIZE_T bytes = static_cast<SIZE_T>(candidateCount_ * sizeof(uint64_t));
	auto* addresses = static_cast<uint64_t*>(VirtualAlloc(nullptr, bytes,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!addresses) return false;
	auto* values = static_cast<uint64_t*>(VirtualAlloc(nullptr, bytes,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!values) {
		VirtualFree(addresses, 0, MEM_RELEASE);
		return false;
	}
	uint64_t out = 0;
	for (uint32_t i = 0; i < snapshotRegionCount_; ++i) {
		const auto& region = snapshotRegions_[i];
		for (uint64_t slot = 0; slot < region.slots; ++slot) {
			if (!BitSet(region.alive, slot)) continue;
			const uint64_t address = region.base + slot * alignment_;
			addresses[out] = address;
			values[out] = LoadRaw(region.bytes + (address - region.base), valueSize_);
			++out;
		}
	}
	addresses_ = addresses;
	values_ = values;
	listCapacity_ = candidateCount_;
	FreeSnapshot();
	mode_ = ValueScanMode::List;
	return true;
}

bool ValueScanner::Next(const ValueScanRequest& request, ValueScanResponse& response) {
	if (mode_ == ValueScanMode::None) {
		response.failure = ValueScanFailure::NoSession;
		return false;
	}
	if (request.valueType != ValueScanType::None && request.valueType != valueType_) {
		response.failure = ValueScanFailure::TypeMismatch;
		return false;
	}
	if (request.compare > ValueScanCompare::DecreasedBy) {
		response.failure = ValueScanFailure::InvalidRequest;
		return false;
	}
	auto* scratch = static_cast<uint8_t*>(VirtualAlloc(nullptr, kChunkSize,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!scratch) {
		response.failure = ValueScanFailure::AllocationFailed;
		return false;
	}

	if (mode_ == ValueScanMode::List) {
		uint64_t out = 0;
		uint64_t index = 0;
		while (index < candidateCount_) {
			const uint64_t start = addresses_[index];
			MEMORY_BASIC_INFORMATION mbi{};
			if (!VirtualQuery(reinterpret_cast<LPCVOID>(start), &mbi, sizeof(mbi))
				|| mbi.State != MEM_COMMIT || !IsReadable(mbi.Protect)) {
				++index;
				continue;
			}
			const uint64_t regionEnd = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
			const uint64_t available = regionEnd > start ? regionEnd - start : 0;
			const size_t len = static_cast<size_t>(available < kChunkSize ? available : kChunkSize);
			uint64_t groupEnd = index;
			while (groupEnd < candidateCount_ && addresses_[groupEnd] >= start
				&& addresses_[groupEnd] + valueSize_ <= start + len) ++groupEnd;
			if (len >= valueSize_ && SafeCopyMemory(scratch, reinterpret_cast<const void*>(start), len)) {
				BreakpointManager::Instance().MaskBreakpointsInBuffer(start, scratch, len);
				response.scannedBytes += len;
				for (uint64_t i = index; i < groupEnd; ++i) {
					const uint64_t raw = LoadRaw(scratch + (addresses_[i] - start), valueSize_);
					if (Matches(valueType_, raw, values_[i], request.value, request.value2, request.compare)) {
						addresses_[out] = addresses_[i];
						values_[out] = raw;
						++out;
					}
				}
			}
			index = groupEnd > index ? groupEnd : index + 1;
		}
		candidateCount_ = out;
	} else {
		uint64_t alive = 0;
		for (uint32_t i = 0; i < snapshotRegionCount_; ++i) {
			auto& region = snapshotRegions_[i];
			uint64_t slot = 0;
			while (slot < region.slots) {
				const uint64_t address = region.base + slot * alignment_;
				const uint64_t remaining = region.size - (address - region.base);
				const size_t len = static_cast<size_t>(remaining < kChunkSize ? remaining : kChunkSize);
				const uint64_t slotsInChunk = len < valueSize_ ? 0 : 1 + (len - valueSize_) / alignment_;
				if (!slotsInChunk) break;
				const bool readable = SafeCopyMemory(scratch, reinterpret_cast<const void*>(address), len);
				if (readable) {
					BreakpointManager::Instance().MaskBreakpointsInBuffer(address, scratch, len);
					response.scannedBytes += len;
				}
				for (uint64_t j = 0; j < slotsInChunk; ++j) {
					const uint64_t bit = slot + j;
					if (!BitSet(region.alive, bit)) continue;
					const uint64_t offset = address - region.base + j * alignment_;
					const uint64_t previous = LoadRaw(region.bytes + offset, valueSize_);
					const uint64_t raw = readable ? LoadRaw(scratch + j * alignment_, valueSize_) : 0;
					if (!readable || !Matches(valueType_, raw, previous,
						request.value, request.value2, request.compare)) {
						ClearBit(region.alive, bit);
					} else {
						memcpy(region.bytes + offset, scratch + j * alignment_, valueSize_);
						++alive;
					}
				}
				slot += slotsInChunk;
			}
		}
		candidateCount_ = alive;
		if (candidateCount_ <= kListCap && !ConvertSnapshotToList()) {
			VirtualFree(scratch, 0, MEM_RELEASE);
			response.failure = ValueScanFailure::AllocationFailed;
			return false;
		}
	}

	VirtualFree(scratch, 0, MEM_RELEASE);
	return true;
}

bool ValueScanner::Page(const ValueScanRequest& request, ValueScanResponse& response,
	ValueScanEntry* entries) const {
	if (mode_ == ValueScanMode::None) {
		response.failure = ValueScanFailure::NoSession;
		return false;
	}
	if (request.offset >= candidateCount_) return true;
	const uint64_t wanted = (std::min)(static_cast<uint64_t>(request.maxResults),
		candidateCount_ - request.offset);
	if (mode_ == ValueScanMode::List) {
		for (uint64_t i = 0; i < wanted; ++i) {
			const uint64_t source = request.offset + i;
			entries[i] = {addresses_[source], values_[source]};
		}
		response.count = static_cast<uint32_t>(wanted);
		return true;
	}

	uint64_t seen = 0;
	uint64_t out = 0;
	for (uint32_t i = 0; i < snapshotRegionCount_ && out < wanted; ++i) {
		const auto& region = snapshotRegions_[i];
		for (uint64_t slot = 0; slot < region.slots && out < wanted; ++slot) {
			if (!BitSet(region.alive, slot)) continue;
			if (seen++ < request.offset) continue;
			const uint64_t address = region.base + slot * alignment_;
			entries[out++] = {address, LoadRaw(region.bytes + (address - region.base), valueSize_)};
		}
	}
	response.count = static_cast<uint32_t>(out);
	return true;
}

void ValueScanner::Scan(const ValueScanRequest& request, ValueScanResponse& response,
	ValueScanEntry* entries, uint64_t excludeStart, uint64_t excludeEnd) {
	response = {};
	response.status = IpcStatus::Error;
	response.failure = ValueScanFailure::None;

	bool ok = false;
	switch (request.operation) {
	case ValueScanOperation::First:
		ok = First(request, response, excludeStart, excludeEnd);
		break;
	case ValueScanOperation::Next:
		ok = Next(request, response);
		break;
	case ValueScanOperation::Results:
		ok = mode_ != ValueScanMode::None;
		if (!ok) response.failure = ValueScanFailure::NoSession;
		break;
	case ValueScanOperation::Reset:
		Reset();
		ok = true;
		break;
	default:
		response.failure = ValueScanFailure::InvalidRequest;
		break;
	}

	response.mode = mode_;
	response.valueType = valueType_;
	response.candidates = candidateCount_;
	if (ok && request.operation != ValueScanOperation::Reset)
		ok = Page(request, response, entries);
	response.status = ok ? IpcStatus::Ok : IpcStatus::Error;
}


namespace {
std::atomic<uint64_t> scanIdentity{1};
struct ScanFailure { ValueScanFailure reason; };
uint64_t BlockPayload(uint32_t span, uint32_t slots, uint32_t count, bool dense) {
    return dense ? uint64_t(span) + (uint64_t(slots) + 7) / 8 : uint64_t(count) * sizeof(ValueScanEntry);
}
}
bool ValueScanner::Generation::Read(const Block& b, std::vector<uint8_t>& out) const {
    const uint64_t size = BlockPayload(b.span, b.slots, b.count, b.dense);
    out.resize(static_cast<size_t>(size));
    if (file == INVALID_HANDLE_VALUE) { out = b.memory; return out.size() == size; }
    std::lock_guard<std::mutex> lock(ioMutex);
    LARGE_INTEGER pos{}; pos.QuadPart = b.offset;
    DWORD got = 0;
    return SetFilePointerEx(file, pos, nullptr, FILE_BEGIN) &&
        ReadFile(file, out.data(), static_cast<DWORD>(size), &got, nullptr) && got == size;
}
std::pair<uint64_t,uint64_t> ValueScanner::RetainedBytes() const {
    uint64_t ram = 0, disk = 0;
    auto add = [&](const std::shared_ptr<Generation>& g) {
        if (!g) return;
        ram += sizeof(Generation) + g->blocks.capacity() * sizeof(Block);
        if (g->file == INVALID_HANDLE_VALUE) ram += g->bytes; else disk += g->bytes;
    };
    add(current_); for (const auto& g : history_) add(g);
    ram+=listCapacity_*2*sizeof(uint64_t);
    for(uint32_t i=0;i<snapshotRegionCount_;++i)ram+=snapshotRegions_[i].size+(snapshotRegions_[i].slots+7)/8;
    ram+=uint64_t(snapshotRegionCount_)*sizeof(SnapshotRegion);
    return {ram,disk};
}
void ValueScanner::StopWorker() {
    cancel_.store(true);
    if (worker_.joinable()) worker_.join();
}
bool ValueScanner::ExtendedBusy() {
    std::lock_guard<std::mutex> lock(jobMutex_);
    return job_.state == ValueScanJobState::Running || job_.state == ValueScanJobState::Cancelling;
}
void ValueScanner::ResetExtended() {
    std::lock_guard<std::mutex> control(controlMutex_);
    StopWorker();
    std::lock_guard<std::mutex> lock(jobMutex_);
    current_.reset(); history_.clear(); job_ = {}; cancel_.store(false);
}
void ValueScanner::SnapshotV2(ValueScanResponseV2& response, std::shared_ptr<Generation>* generation) {
    std::lock_guard<std::mutex> lock(jobMutex_);
    if(generation)*generation=current_;
    response = job_;
    response.version = 2; response.headerSize = sizeof(response);
    response.scan.status = IpcStatus::Ok; response.scan.count = 0;
    response.undoAvailable = static_cast<uint32_t>(history_.size());
    response.elapsedMs = jobStart_ && (response.state == ValueScanJobState::Running ||
        response.state == ValueScanJobState::Cancelling) ? clock_() - jobStart_ : job_.elapsedMs;
    auto used = RetainedBytes();
    response.retainedRamBytes = used.first; response.retainedDiskBytes = used.second;
    if (current_) {
        response.generationId = current_->id;
        response.scan.candidates = current_->candidates;
        response.scan.valueType = current_->type;
        response.scan.mode = current_->file == INVALID_HANDLE_VALUE ? ValueScanMode::Snapshot : ValueScanMode::Disk;
        response.storage = current_->file == INVALID_HANDLE_VALUE ? ValueScanStorage::Ram : ValueScanStorage::File;
    } else {
        response.generationId = response.scan.candidates = 0;
        response.scan.mode = ValueScanMode::None; response.scan.valueType = ValueScanType::None;
    }
}
bool ValueScanner::PageV2(const Generation& g, uint64_t offset, uint32_t max,
    std::vector<ValueScanEntry>& entries) {
    entries.clear();
    if (offset >= g.candidates) return true;
    std::vector<uint8_t> data;
    for (const auto& block : g.blocks) {
        if (offset >= block.count) { offset -= block.count; continue; }
        if (!g.Read(block,data)) return false;
        if (block.dense) {
            const uint8_t* bits = data.data() + block.span;
            for (uint32_t i = 0; i < block.slots && entries.size() < max; ++i) {
                if (!BitSet(bits,i)) continue;
                if (offset) { --offset; continue; }
                entries.push_back({block.base + uint64_t(i)*g.alignment,
                    LoadRaw(data.data() + uint64_t(i)*g.alignment,g.size)});
            }
        } else {
            const auto* values = reinterpret_cast<const ValueScanEntry*>(data.data());
            for (uint32_t i = static_cast<uint32_t>(offset); i < block.count && entries.size() < max; ++i)
                entries.push_back(values[i]);
            offset = 0;
        }
        if (entries.size() >= max) break;
    }
    return true;
}
void ValueScanner::Progress(ValueScanPhase phase,uint64_t processed,uint64_t total,
    uint64_t matched,uint64_t bytes,bool notify,bool force) {
    bool emit = false;
    {
        std::lock_guard<std::mutex> lock(jobMutex_);
        job_.phase = phase; job_.processed = processed; job_.total = total;
        job_.matched = matched; job_.scan.scannedBytes = bytes;
        job_.elapsedMs = clock_() - jobStart_;
        const uint64_t now = clock_();
        emit = notify && (force || phase != lastPhase_ || now-lastEvent_ >= 10000);
        if (emit) { lastEvent_ = now; lastPhase_ = phase; ++job_.sequence; }
    }
    if (!emit) return;
    try { // Notification allocation/transport failure must never escape into the target.
    ValueScanResponseV2 event{}; SnapshotV2(event);
    // No pipe I/O while holding scan-state locks. The transport bounds writes.
    std::vector<ValueScanEntry> entries;
    std::shared_ptr<Generation> generation;
    ValueScanRequestV2 original{};
    { std::lock_guard<std::mutex> lock(jobMutex_); generation=current_;original=jobRequest_; }
    if(phase==ValueScanPhase::Finished && event.state==ValueScanJobState::Completed && generation &&
        !(original.flags&kValueScanSummary) && generation->candidates<=original.summaryThreshold &&
        PageV2(*generation,0,std::min<uint32_t>(32,original.scan.maxResults),entries))
        event.scan.count=static_cast<uint32_t>(entries.size());
    std::vector<uint8_t> payload(sizeof(event)+entries.size()*sizeof(ValueScanEntry));
    memcpy(payload.data(),&event,sizeof(event));
    if(!entries.empty())memcpy(payload.data()+sizeof(event),entries.data(),entries.size()*sizeof(ValueScanEntry));
    PipeServer::Instance().SendEvent(static_cast<uint32_t>(IpcEvent::ValueScanProgress),payload.data(),static_cast<uint32_t>(payload.size()));
    } catch(...) { /* Explicit status can recover the authoritative job state. */ }
}
void ValueScanner::ExecuteV2(ValueScanRequestV2 req,uint64_t excludeStart,uint64_t excludeEnd) {
    const bool notify = (req.flags & kValueScanNotify) != 0;
    const bool first = req.scan.operation == ValueScanOperation::First;
    std::shared_ptr<Generation> source;
    std::pair<uint64_t,uint64_t> retained;
    { std::lock_guard<std::mutex> lock(jobMutex_); source=current_; retained=RetainedBytes(); }
    uint64_t processed=0,total=0,matched=0,readBytes=0,unreadable=0;
    ScanRegion* regions=nullptr; uint32_t regionCount=0;
    std::shared_ptr<Generation> stage;
    ValueScanFailure failure=ValueScanFailure::None;
    try {
        if(!first&&!source)throw ScanFailure{ValueScanFailure::NoSession};
        stage=std::make_shared<Generation>();
        stage->id=scanIdentity.fetch_add(1);
        stage->type=first?req.scan.valueType:source->type;
        stage->size=first?ValueSize(req.scan.valueType):source->size;
        stage->alignment=first?req.scan.alignment:source->alignment;
        auto checkCancel=[&] { if(cancel_.load()) throw ScanFailure{ValueScanFailure::Cancelled}; };
        uint64_t estimate=0,maxChunks=0;
        if(first) {
            Progress(ValueScanPhase::Discovering,0,0,0,0,notify,true);
            const uint64_t availableRam=retained.first<req.ramBudgetBytes?req.ramBudgetBytes-retained.first:0;
            if(availableRam<=1024*1024)throw ScanFailure{ValueScanFailure::BudgetExceeded};
            if(!DiscoverRegions(req.scan,stage->size,regions,regionCount,estimate,UINT64_MAX,&cancel_,
                [&](uint64_t visited){ Progress(ValueScanPhase::Discovering,visited,0,0,0,notify); },
                availableRam-1024*1024)) {
                checkCancel();throw ScanFailure{estimate==UINT64_MAX?ValueScanFailure::BudgetExceeded:ValueScanFailure::AllocationFailed};
            }
            estimate=0;
            for(uint32_t i=0;i<regionCount;++i) {
                checkCancel(); const auto& r=regions[i]; total+=r.slots;
                // Chunk-local copies retain overlap between unaligned values.
                const uint64_t chunkSlots=1+(kChunkSize-stage->size)/stage->alignment;
                const uint64_t chunks=(r.slots+chunkSlots-1)/chunkSlots;
                maxChunks+=chunks;
                const uint64_t payload=r.slots*stage->alignment+chunks*(stage->size+8)+((r.slots+7)/8);
                if(payload>UINT64_MAX-estimate) throw ScanFailure{ValueScanFailure::BudgetExceeded};
                estimate+=payload;
            }
        } else {
            if(!source) throw ScanFailure{ValueScanFailure::NoSession};
            total=source->candidates; estimate=source->bytes;maxChunks=source->blocks.size();
        }
        { std::lock_guard<std::mutex> lock(jobMutex_); job_.estimatedBytes=estimate; }
        // A bounded workspace plus metadata capacity is reserved independently of payload.
        const uint64_t workspace=1024*1024+uint64_t(regionCount)*sizeof(ScanRegion);
        const uint64_t meta=workspace+sizeof(Generation)+2*maxChunks*sizeof(Block);
        const bool file=req.storage==ValueScanStorage::File || (req.storage==ValueScanStorage::Auto &&
            (retained.first>req.ramBudgetBytes || estimate+meta>req.ramBudgetBytes-retained.first));
        if(retained.first>req.ramBudgetBytes || meta>req.ramBudgetBytes-retained.first)
            throw ScanFailure{ValueScanFailure::BudgetExceeded};
        if(file) {
            if(retained.second>req.diskBudgetBytes || estimate>req.diskBudgetBytes-retained.second)
                throw ScanFailure{ValueScanFailure::BudgetExceeded};
            wchar_t path[MAX_PATH]{},name[MAX_PATH]{};
            const DWORD pathLength=GetTempPathW(MAX_PATH,path);
            if(!pathLength || pathLength>=MAX_PATH || pathLength+64>=MAX_PATH)
                throw ScanFailure{ValueScanFailure::StorageFailed};
            ULARGE_INTEGER available{};
            if(!GetDiskFreeSpaceExW(path,&available,nullptr,nullptr) || available.QuadPart<estimate+16*1024*1024)
                throw ScanFailure{ValueScanFailure::BudgetExceeded};
            checkCancel();
            for(unsigned attempt=0;attempt<8;++attempt) {
                swprintf_s(name,L"%svsc-%08lX-%016llX-%016llX.tmp",path,GetCurrentProcessId(),clock_(),scanIdentity.fetch_add(1));
                stage->file=CreateFileW(name,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_DELETE,nullptr,
                    CREATE_NEW,FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_DELETE_ON_CLOSE|FILE_FLAG_SEQUENTIAL_SCAN,nullptr);
                if(stage->file!=INVALID_HANDLE_VALUE)break;
                if(GetLastError()!=ERROR_FILE_EXISTS&&GetLastError()!=ERROR_ALREADY_EXISTS)break;
            }
            if(stage->file==INVALID_HANDLE_VALUE)throw ScanFailure{ValueScanFailure::StorageFailed};
        } else if(estimate+meta>req.ramBudgetBytes-retained.first)
            throw ScanFailure{ValueScanFailure::BudgetExceeded};
        auto append=[&](uint64_t base,uint32_t span,uint32_t slots,const std::vector<uint8_t>& raw,
            const std::vector<uint8_t>& bits,uint32_t count) {
            if(!count) return;
            checkCancel();
            Block b; b.base=base;b.span=span;b.slots=slots;b.count=count;
            b.dense=uint64_t(span)+(slots+7)/8 <= uint64_t(count)*sizeof(ValueScanEntry);
            const uint64_t size=BlockPayload(span,slots,count,b.dense);
            std::vector<uint8_t> payload(static_cast<size_t>(size));
            if(b.dense) { memcpy(payload.data(),raw.data(),span);memcpy(payload.data()+span,bits.data(),bits.size()); }
            else {
                auto* values=reinterpret_cast<ValueScanEntry*>(payload.data()); uint32_t out=0;
                for(uint32_t i=0;i<slots;++i)if(BitSet(bits.data(),i))
                    values[out++]={base+uint64_t(i)*stage->alignment,LoadRaw(raw.data()+uint64_t(i)*stage->alignment,stage->size)};
            }
            const uint64_t metadata=workspace+sizeof(Generation)+2*(stage->blocks.size()+1)*sizeof(Block);
            if(retained.first+metadata+(file?0:stage->bytes+size)>req.ramBudgetBytes ||
                (file && retained.second+stage->bytes+size>req.diskBudgetBytes))
                throw ScanFailure{ValueScanFailure::BudgetExceeded};
            b.offset=stage->bytes;
            if(file) {
                DWORD written=0;
                if(!WriteFile(stage->file,payload.data(),static_cast<DWORD>(size),&written,nullptr)||written!=size)
                    throw ScanFailure{ValueScanFailure::StorageFailed};
            } else b.memory=std::move(payload);
            stage->blocks.push_back(std::move(b));stage->bytes+=size;stage->candidates+=count;
        };
        const auto phase=first?ValueScanPhase::Capturing:ValueScanPhase::Filtering;
        Progress(phase,0,total,0,0,notify,true);
        if(maxChunks>SIZE_MAX/sizeof(Block))throw ScanFailure{ValueScanFailure::BudgetExceeded};
        stage->blocks.reserve(static_cast<size_t>(maxChunks));
        std::vector<uint8_t> raw(kChunkSize),previous,bits;
        if(first) {
            for(uint32_t region=0;region<regionCount;++region) {
                const auto& r=regions[region];
                const uint64_t perChunk=1+(kChunkSize-stage->size)/stage->alignment;
                for(uint64_t slot=0;slot<r.slots;) {
                    checkCancel();
                    const uint32_t slots=static_cast<uint32_t>(std::min<uint64_t>(perChunk,r.slots-slot));
                    const uint64_t base=r.first+slot*stage->alignment;
                    const uint32_t span=(slots-1)*stage->alignment+stage->size;
                    bits.assign((slots+7)/8,0); uint32_t count=0;
                    if(SafeCopyMemory(raw.data(),reinterpret_cast<const void*>(base),span)) {
                        BreakpointManager::Instance().MaskBreakpointsInBuffer(base,raw.data(),span);readBytes+=span;
                        for(uint32_t i=0;i<slots;++i)if(!Overlaps(base+uint64_t(i)*stage->alignment,stage->size,excludeStart,excludeEnd) &&
                            Matches(stage->type,LoadRaw(raw.data()+uint64_t(i)*stage->alignment,stage->size),0,
                                req.scan.value,req.scan.value2,req.scan.compare)) { SetBit(bits.data(),i);++count; }
                        append(base,span,slots,raw,bits,count);
                    } else unreadable+=span;
                    processed+=slots;matched+=count;slot+=slots;
                    Progress(phase,processed,total,matched,readBytes,notify);
                }
            }
        } else {
            for(const auto& b:source->blocks) {
                checkCancel();
                if(!source->Read(b,previous)) throw ScanFailure{ValueScanFailure::StorageFailed};
                const bool readable=SafeCopyMemory(raw.data(),reinterpret_cast<const void*>(b.base),b.span);
                bits.assign((b.slots+7)/8,0);uint32_t count=0;
                if(readable) {
                    BreakpointManager::Instance().MaskBreakpointsInBuffer(b.base,raw.data(),b.span);readBytes+=b.span;
                    if(b.dense) {
                        for(uint32_t i=0;i<b.slots;++i)if(BitSet(previous.data()+b.span,i)) {
                            const uint64_t off=uint64_t(i)*stage->alignment;
                            if(Matches(stage->type,LoadRaw(raw.data()+off,stage->size),LoadRaw(previous.data()+off,stage->size),
                                req.scan.value,req.scan.value2,req.scan.compare)) { SetBit(bits.data(),i);++count; }
                        }
                    } else {
                        const auto* values=reinterpret_cast<const ValueScanEntry*>(previous.data());
                        for(uint32_t i=0;i<b.count;++i) {
                            const uint64_t off=values[i].address-b.base;
                            if(Matches(stage->type,LoadRaw(raw.data()+off,stage->size),values[i].value,
                                req.scan.value,req.scan.value2,req.scan.compare)) {
                                SetBit(bits.data(),off/stage->alignment);++count;
                            }
                        }
                    }
                    append(b.base,b.span,b.slots,raw,bits,count);
                } else unreadable+=b.span;
                processed+=b.count;matched+=count;
                Progress(phase,processed,total,matched,readBytes,notify);
            }
        }
        Progress(ValueScanPhase::Committing,processed,total,matched,readBytes,notify,true);
        if(file && !FlushFileBuffers(stage->file)) throw ScanFailure{ValueScanFailure::StorageFailed};
        checkCancel();
        std::deque<std::shared_ptr<Generation>> nextHistory;
        if(!first) { std::lock_guard<std::mutex> lock(jobMutex_); nextHistory=history_; }
        if(!first && source && req.undoDepth)nextHistory.push_back(source);
        while(nextHistory.size()>req.undoDepth)nextHistory.pop_front();
        {
            std::lock_guard<std::mutex> lock(jobMutex_);
            // Cancellation is rechecked after file I/O and immediately before commit.
            checkCancel();
            if(first) ClearLegacy();
            history_.swap(nextHistory);
            current_=stage;job_.state=ValueScanJobState::Completed;
            job_.scan.failure=ValueScanFailure::None;job_.unreadableBytes=unreadable;
        }
    } catch(const ScanFailure& e) { failure=e.reason; }
      catch(...) { failure=ValueScanFailure::AllocationFailed; }
    if(regions)VirtualFree(regions,0,MEM_RELEASE);
    stage.reset();
    if(failure!=ValueScanFailure::None) {
        std::lock_guard<std::mutex> lock(jobMutex_);
        job_.state=failure==ValueScanFailure::Cancelled?ValueScanJobState::Cancelled:ValueScanJobState::Failed;
        job_.scan.failure=failure;job_.unreadableBytes=unreadable;
    }
    Progress(ValueScanPhase::Finished,processed,total,matched,readBytes,notify,true);
}
void ValueScanner::ScanV2(const ValueScanRequestV2& request,ValueScanResponseV2& response,
    std::vector<ValueScanEntry>& entries,uint64_t excludeStart,uint64_t excludeEnd) {
    std::lock_guard<std::mutex> control(controlMutex_);
    entries.clear();
    auto fail=[&](ValueScanFailure why) { SnapshotV2(response);response.scan.status=IpcStatus::InvalidState;response.scan.failure=why; };
    const auto op=request.scan.operation;
    if(request.version!=2 || request.scan.maxResults>1000 || !request.scan.maxResults ||
        request.scan.operation>ValueScanOperation::Undo || request.storage>ValueScanStorage::File ||
        request.scan.valueType>ValueScanType::F64 || request.scan.compare>ValueScanCompare::DecreasedBy ||
        request.scan.writable>RegionFilter::Exclude || request.scan.executable>RegionFilter::Exclude ||
        (request.scan.typeMask&~7) || request.scan.reserved[0] || request.scan.reserved[1] ||
        ((request.flags&kValueScanNotify)&&!(request.flags&kValueScanAsync)) ||
        ((request.flags&kValueScanAsync)&&op!=ValueScanOperation::First&&op!=ValueScanOperation::Next) ||
        (request.jobId&&op!=ValueScanOperation::Status&&op!=ValueScanOperation::Cancel) ||
        request.flags & ~(kValueScanAsync|kValueScanNotify|kValueScanSummary|kValueScanList) ||
        ((request.flags&kValueScanSummary)&&(request.flags&kValueScanList)) ||
        request.undoDepth>8 || request.summaryThreshold>32 ||
        request.ramBudgetBytes<64*1024 || request.ramBudgetBytes>1024ull*1024*1024 ||
        request.diskBudgetBytes<64*1024 || request.diskBudgetBytes>1024ull*1024*1024*1024 ||
        std::any_of(std::begin(request.reserved),std::end(request.reserved),[](uint8_t b){return b!=0;})) {
        fail(ValueScanFailure::InvalidRequest);return;
    }
    if(op==ValueScanOperation::First) {
        uint64_t lo=0,hi=0;UserSpaceBounds(request.scan.startAddress,request.scan.endAddress,lo,hi);
        if(lo>=hi || (request.scan.endAddress&&request.scan.endAddress<=request.scan.startAddress) ||
            request.scan.startAddress>UINTPTR_MAX || request.scan.endAddress>UINTPTR_MAX) {
            fail(ValueScanFailure::InvalidRequest);return;
        }
    }
    if(op==ValueScanOperation::Reset) {
        StopWorker();ClearLegacy();
        { std::lock_guard<std::mutex> lock(jobMutex_);current_.reset();history_.clear();job_={}; }
        SnapshotV2(response);return;
    }
    if(op==ValueScanOperation::Status || op==ValueScanOperation::Cancel) {
        { std::lock_guard<std::mutex> lock(jobMutex_);
          if((op==ValueScanOperation::Cancel && !request.jobId) || (request.jobId&&request.jobId!=job_.jobId)) {
              response={};response.version=2;response.headerSize=sizeof(response);
              response.scan.status=IpcStatus::InvalidState;response.scan.failure=ValueScanFailure::StaleJob;return;
          }
          if(op==ValueScanOperation::Cancel && job_.state==ValueScanJobState::Running) {
              cancel_.store(true);job_.state=ValueScanJobState::Cancelling;
          }
        }
    } else if(op==ValueScanOperation::Undo) {
        if(ExtendedBusy()) { fail(ValueScanFailure::Busy);return; }
        if(worker_.joinable())worker_.join();
        { std::lock_guard<std::mutex> lock(jobMutex_);
          if(history_.empty()) { response={};response.version=2;response.headerSize=sizeof(response);
              response.scan.status=IpcStatus::InvalidState;response.scan.failure=ValueScanFailure::NoHistory;return; }
          current_=history_.back();history_.pop_back();
          const uint64_t session=job_.sessionId;
          job_={};job_.sessionId=session;job_.jobId=scanIdentity.fetch_add(1);
          job_.state=ValueScanJobState::Completed;job_.phase=ValueScanPhase::Finished;
          job_.matched=current_->candidates;job_.processed=job_.total=current_->candidates;jobStart_=0;
        }
    } else if(op==ValueScanOperation::First || op==ValueScanOperation::Next) {
        if(ExtendedBusy()) { fail(ValueScanFailure::Busy);return; }
        if(worker_.joinable())worker_.join();
        const bool first=op==ValueScanOperation::First;
        if((first && (!ValueSize(request.scan.valueType)||!request.scan.alignment||request.scan.alignment>4096||
            request.scan.compare>ValueScanCompare::Unknown)) ||
            (!first && request.scan.compare>ValueScanCompare::DecreasedBy)) {fail(ValueScanFailure::InvalidRequest);return;}
        { std::lock_guard<std::mutex> lock(jobMutex_);
          if(!first && (!current_ || (request.scan.valueType!=ValueScanType::None && request.scan.valueType!=current_->type))) {
              response={};response.version=2;response.headerSize=sizeof(response);response.scan.status=IpcStatus::InvalidState;
              response.scan.failure=current_?ValueScanFailure::TypeMismatch:ValueScanFailure::NoSession;return;
          }
          const uint64_t session=job_.sessionId?job_.sessionId:scanIdentity.fetch_add(1);
          job_={};jobRequest_=request;job_.sessionId=session;job_.jobId=scanIdentity.fetch_add(1);
          job_.state=ValueScanJobState::Running;jobStart_=clock_();lastEvent_=0;
          lastPhase_=ValueScanPhase::Idle;cancel_.store(false);
        }
        if(request.flags&kValueScanAsync) {
            SnapshotV2(response); // immutable admission receipt, even if a tiny job finishes first
            try {
                std::mutex readyMutex;std::condition_variable readyCv;bool ready=false,registrationOkay=false;
                worker_=std::thread([this,request,excludeStart,excludeEnd,&readyMutex,&readyCv,&ready,&registrationOkay] {
                    const uint32_t tid=GetCurrentThreadId();
                    VehHandler::Instance().SetScanWorkerThread(tid);
                    bool registered=false;
                    try {
                        ThreadManager::Instance().RegisterInternalThread(tid);registered=true;
                    } catch(...) {
                        std::lock_guard<std::mutex> lock(jobMutex_);job_.state=ValueScanJobState::Failed;
                        job_.scan.failure=ValueScanFailure::AllocationFailed;
                    }
                    {std::lock_guard<std::mutex> lock(readyMutex);registrationOkay=registered;ready=true;readyCv.notify_one();}
                    if(registered) {
                        try { ExecuteV2(request,excludeStart,excludeEnd); }
                        catch(...) {
                            std::lock_guard<std::mutex> lock(jobMutex_);job_.state=ValueScanJobState::Failed;
                            job_.scan.failure=ValueScanFailure::AllocationFailed;
                        }
                        ThreadManager::Instance().UnregisterInternalThread(tid);
                    }
                    VehHandler::Instance().SetScanWorkerThread(0);
                });
                // No control receipt until Pause/Freeze will exclude this worker.
                std::unique_lock<std::mutex> lock(readyMutex);readyCv.wait(lock,[&]{return ready;});
                if(!registrationOkay)fail(ValueScanFailure::AllocationFailed);
            } catch(...) {
                { std::lock_guard<std::mutex> lock(jobMutex_);job_.state=ValueScanJobState::Failed;
                  job_.scan.failure=ValueScanFailure::AllocationFailed; }
                fail(ValueScanFailure::AllocationFailed);
            }
            return;
        }
        ExecuteV2(request,excludeStart,excludeEnd);
    }
    std::shared_ptr<Generation> g;
    SnapshotV2(response,&g);
    if((op==ValueScanOperation::First || op==ValueScanOperation::Next) && response.state==ValueScanJobState::Failed)
        response.scan.status=IpcStatus::Error;
    if(op==ValueScanOperation::Results&&!g) {fail(ValueScanFailure::NoSession);return;}
    const bool show=op==ValueScanOperation::Results || (request.flags&kValueScanList) ||
        (!(request.flags&kValueScanSummary) && g && g->candidates<=request.summaryThreshold &&
         response.state!=ValueScanJobState::Running && response.state!=ValueScanJobState::Cancelling);
    if(show && g) {
        if(!PageV2(*g,request.scan.offset,request.scan.maxResults,entries)) {
            response.scan.status=IpcStatus::Error;response.scan.failure=ValueScanFailure::StorageFailed;return;
        }
        response.scan.count=static_cast<uint32_t>(entries.size());
    }
}

} // namespace veh
