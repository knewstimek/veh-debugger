#pragma once
#include "ipc_protocol.h"
#include <array>
#include <cstring>

namespace veh {
// A bounded record encoder, not an execution engine. Only observed complete
// cycles are encoded. The sink receives immutable records in execution order.
class TracePathCompressor {
public:
    static constexpr uint32_t kMaxPattern = 32;
    void Reset() { historyCount_ = patternSize_ = pendingCount_ = 0; repeats_ = stride_ = 0; }

    template<class Sink> void Flush(Sink&& sink, bool retainRawHistory = false) {
        const bool compressed = repeats_ && (repeats_ > 1 || patternSize_ > 1);
        if (compressed) {
            TraceBasicBlockEventEntry marker{};
            marker.sequence = pattern_[0].sequence + stride_;
            marker.source = patternSize_;
            marker.sourceInstruction = repeats_;
            marker.target = stride_;
            marker.threadId = pattern_[0].threadId;
            marker.codeVersion = UINT32_MAX;
            marker.type = TraceBasicBlockEventType::Repeat;
            sink(marker);
            historyCount_ = 0;
        } else if (repeats_) {
            // A one-record template repeated only once saves no space. Keep it
            // raw and retain history so a longer surrounding path can be found.
            auto raw = pattern_[0];
            raw.sequence += stride_;
            sink(raw);
            Remember(raw);
        }
        for (uint32_t i = 0; i < pendingCount_; ++i) {
            sink(pending_[i]);
            Remember(pending_[i]);
        }
        patternSize_ = pendingCount_ = 0;
        repeats_ = stride_ = 0;
        if (!retainRawHistory) historyCount_ = 0;
    }

    template<class Sink> void Push(const TraceBasicBlockEventEntry& event, Sink&& sink) {
        if (event.type != TraceBasicBlockEventType::Edge || event.exceptionCode ||
            event.edgeKind == TraceBasicBlockEdgeKind::Exception || event.codeVersion == UINT32_MAX) {
            Flush(sink);
            sink(event);
            return;
        }
        if (patternSize_) {
            const auto& expected = pattern_[pendingCount_];
            // Actual trace steps are bounded to 5M, but validate arithmetic here
            // as well so this encoder remains safe with synthetic inputs.
            const bool fits = repeats_ < UINT64_MAX && stride_ &&
                repeats_ + 1 <= (UINT64_MAX - expected.sequence) / stride_;
            if (fits && Same(expected, event) &&
                event.sequence == expected.sequence + (repeats_ + 1) * stride_) {
                pending_[pendingCount_++] = event;
                if (pendingCount_ == patternSize_) { ++repeats_; pendingCount_ = 0; }
                return;
            }
            Flush(sink, true);
        }
        // Most recent matching suffix gives a short bounded template. Matching
        // its first event is only a candidate: all remaining events must match.
        for (uint32_t distance = 1; distance <= historyCount_; ++distance) {
            const uint32_t start = historyCount_ - distance;
            const auto& first = history_[start];
            if (!Same(first, event) || event.sequence <= history_[historyCount_ - 1].sequence) continue;
            stride_ = event.sequence - first.sequence;
            patternSize_ = distance;
            for (uint32_t i = 0; i < distance; ++i) pattern_[i] = history_[start + i];
            pending_[0] = event;
            pendingCount_ = 1;
            if (distance == 1) { repeats_ = 1; pendingCount_ = 0; }
            return;
        }
        sink(event);
        Remember(event);
    }
private:
    void Remember(const TraceBasicBlockEventEntry& event) {
        if (historyCount_ == kMaxPattern) {
            for (uint32_t i = 1; i < kMaxPattern; ++i) history_[i - 1] = history_[i];
            --historyCount_;
        }
        history_[historyCount_++] = event;
    }
    static bool Same(const TraceBasicBlockEventEntry& a, const TraceBasicBlockEventEntry& b) {
        return a.source == b.source && a.sourceInstruction == b.sourceInstruction &&
            a.target == b.target && a.threadId == b.threadId && a.exceptionCode == b.exceptionCode &&
            a.codeVersion == b.codeVersion && a.type == b.type && a.edgeKind == b.edgeKind &&
            a.indirect == b.indirect;
    }
    std::array<TraceBasicBlockEventEntry, kMaxPattern> history_{}, pattern_{}, pending_{};
    uint32_t historyCount_ = 0, patternSize_ = 0, pendingCount_ = 0;
    uint64_t repeats_ = 0, stride_ = 0;
};
// Validates references and arithmetic without expanding potentially large runs.
class TracePathValidator {
public:
    bool Accept(const TraceBasicBlockEventEntry& e) {
        if (e.sequence < lastSequence_ || e.reserved[0] || e.indirect > 1) return false;
        if (haveThread_ && e.threadId != thread_) return false;
        haveThread_ = true; thread_ = e.threadId;
        if (e.type == TraceBasicBlockEventType::Repeat) {
            const uint64_t n = e.source, repeats = e.sourceInstruction, stride = e.target;
            if (!n || n > count_ || n > TracePathCompressor::kMaxPattern || !repeats || !stride ||
                e.exceptionCode || e.indirect || e.codeVersion != UINT32_MAX ||
                e.edgeKind != TraceBasicBlockEdgeKind::Fallthrough) return false;
            const auto& first = history_[count_ - static_cast<uint32_t>(n)];
            const auto& last = history_[count_ - 1];
            if (stride <= last.sequence - first.sequence ||
                stride > UINT64_MAX - first.sequence || e.sequence != first.sequence + stride ||
                repeats > (UINT64_MAX - last.sequence) / stride ||
                repeats > (UINT64_MAX - expanded_) / n) return false;
            for (uint32_t i = count_ - static_cast<uint32_t>(n); i < count_; ++i)
                if (history_[i].type != TraceBasicBlockEventType::Edge ||
                    history_[i].codeVersion == UINT32_MAX || history_[i].exceptionCode ||
                    history_[i].edgeKind == TraceBasicBlockEdgeKind::Exception) return false;
            lastSequence_ = last.sequence + repeats * stride;
            expanded_ += repeats * n;
            count_ = 0;
            return true;
        }
        if (e.type != TraceBasicBlockEventType::BlockEntry && e.type != TraceBasicBlockEventType::Edge)
            return false;
        if (static_cast<uint8_t>(e.edgeKind) > static_cast<uint8_t>(TraceBasicBlockEdgeKind::RangeExit) ||
            expanded_ == UINT64_MAX) return false;
        lastSequence_ = e.sequence;
        ++expanded_;
        if (count_ == TracePathCompressor::kMaxPattern) {
            for (uint32_t i = 1; i < count_; ++i) history_[i - 1] = history_[i];
            --count_;
        }
        history_[count_++] = e;
        return true;
    }
    uint64_t ExpandedCount() const { return expanded_; }
private:
    std::array<TraceBasicBlockEventEntry, TracePathCompressor::kMaxPattern> history_{};
    uint32_t count_ = 0, thread_ = 0;
    uint64_t lastSequence_ = 0, expanded_ = 0;
    bool haveThread_ = false;
};
} // namespace veh
