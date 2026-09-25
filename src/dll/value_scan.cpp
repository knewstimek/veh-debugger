#include "value_scan.h"
#include "memory.h"
#include "breakpoint.h"
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
	ScanRegion*& regions, uint32_t& regionCount, uint64_t& snapshotBytes) {
	regions = nullptr;
	regionCount = 0;
	snapshotBytes = 0;
	uint64_t lo, hi;
	UserSpaceBounds(request.startAddress, request.endAddress, lo, hi);

	uint32_t count = 0;
	for (uint64_t addr = lo; addr < hi;) {
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
				if (snapshotBytes > kSnapshotCap || bytes > kSnapshotCap - snapshotBytes
					|| bitmap > kSnapshotCap - snapshotBytes - bytes) {
					snapshotBytes = kSnapshotCap + 1;
				}
				else snapshotBytes += bytes + bitmap;
			}
		}
		addr = next;
	}

	if (!count) return true;
	regions = static_cast<ScanRegion*>(VirtualAlloc(nullptr, static_cast<SIZE_T>(count) * sizeof(ScanRegion),
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!regions) return false;
	const void* regionAllocation = regions;
	uint32_t filled = 0;
	for (uint64_t addr = lo; addr < hi && filled < count;) {
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
			if (snapshotBytes > kSnapshotCap || bytes > kSnapshotCap - snapshotBytes
				|| bitmap > kSnapshotCap - snapshotBytes - bytes) {
				snapshotBytes = kSnapshotCap + 1;
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

} // namespace veh
