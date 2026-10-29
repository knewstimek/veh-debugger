#include "../src/common/trace_path_compressor.h"
#include <iostream>
#include <stdexcept>
#include <vector>
using namespace veh;
static void Require(bool ok) { if (!ok) throw std::runtime_error("path regression failed"); }
static TraceBasicBlockEventEntry Event(uint64_t seq, uint64_t site, uint32_t version = 0) {
    TraceBasicBlockEventEntry e{};
    e.sequence = seq; e.source = site; e.sourceInstruction = site + 1;
    e.target = site + 2; e.threadId = 7; e.codeVersion = version;
    e.type = TraceBasicBlockEventType::Edge; e.edgeKind = TraceBasicBlockEdgeKind::Branch;
    return e;
}
static bool Equal(const TraceBasicBlockEventEntry& a, const TraceBasicBlockEventEntry& b) {
    return std::memcmp(&a, &b, sizeof(a)) == 0;
}
int main() {
    try {
        for (uint32_t width = 1; width <= 33; ++width) {
            TracePathCompressor codec;
            std::vector<TraceBasicBlockEventEntry> raw, encoded, expanded;
            auto sink = [&](const auto& e) { encoded.push_back(e); };
            uint64_t seq = 0;
            for (uint32_t segment = 0; segment < 6; ++segment) {
                for (uint32_t cycle = 0; cycle < 9; ++cycle) {
                    for (uint32_t i = 0; i < width; ++i) {
                        seq += 1 + i % 3;
                        auto e = Event(seq, 0x1000 + i * 16, segment / 2);
                        if (cycle == 4 && i == width / 2) e.target += 0x100;
                        if (cycle == 6 && i == 0) ++seq; // stride change
                        e.sequence = seq;
                        raw.push_back(e); codec.Push(e, sink);
                    }
                }
                // An incomplete cycle at a collection/version/exception boundary.
                auto tail = Event(++seq, 0x1000, segment / 2);
                raw.push_back(tail); codec.Push(tail, sink);
                codec.Flush(sink);
                seq += 100;
                auto unknown = Event(++seq, 0x9000, UINT32_MAX);
                raw.push_back(unknown); codec.Push(unknown, sink);
                auto exception = Event(++seq, 0x9010);
                exception.edgeKind = TraceBasicBlockEdgeKind::Exception;
                exception.exceptionCode = 0xC000001D;
                raw.push_back(exception); codec.Push(exception, sink);
            }
            codec.Flush(sink);
            TracePathValidator validator;
            for (const auto& e : encoded) {
                Require(validator.Accept(e));
                if (e.type != TraceBasicBlockEventType::Repeat) expanded.push_back(e);
                else {
                    const size_t n = static_cast<size_t>(e.source);
                    std::vector<TraceBasicBlockEventEntry> pattern(expanded.end() - n, expanded.end());
                    for (uint64_t r = 1; r <= e.sourceInstruction; ++r)
                        for (auto item : pattern) { item.sequence += r * e.target; expanded.push_back(item); }
                }
            }
            Require(expanded.size() == raw.size() && validator.ExpandedCount() == raw.size());
            for (size_t i = 0; i < raw.size(); ++i) Require(Equal(raw[i], expanded[i]));
            // Every physical prefix must remain a valid logical prefix on overflow.
            for (size_t cap = 0; cap < encoded.size(); cap += 7) {
                TracePathValidator prefix;
                for (size_t i = 0; i < cap; ++i) Require(prefix.Accept(encoded[i]));
                Require(prefix.ExpandedCount() <= raw.size());
            }
        }
        // A short repeated edge inside a longer changing branch path must not
        // prevent discovery of the surrounding repeated cycle.
        TracePathCompressor nested;
        std::vector<TraceBasicBlockEventEntry> nestedRecords;
        auto nestedSink = [&](const auto& e) { nestedRecords.push_back(e); };
        for (uint64_t i = 0; i < 200; ++i)
            nested.Push(Event(i + 1, (i % 4 < 2) ? 10 : i % 4 + 20), nestedSink);
        nested.Flush(nestedSink);
        Require(nestedRecords.size() < 30);
        TracePathValidator nestedValidator;
        std::vector<TraceBasicBlockEventEntry> nestedExpanded;
        for (const auto& e : nestedRecords) {
            Require(nestedValidator.Accept(e));
            if (e.type != TraceBasicBlockEventType::Repeat) nestedExpanded.push_back(e);
            else {
                const size_t n = static_cast<size_t>(e.source);
                std::vector<TraceBasicBlockEventEntry> pattern(nestedExpanded.end() - n, nestedExpanded.end());
                for (uint64_t r = 1; r <= e.sourceInstruction; ++r)
                    for (auto item : pattern) { item.sequence += r * e.target; nestedExpanded.push_back(item); }
            }
        }
        Require(nestedExpanded.size() == 200 && nestedValidator.ExpandedCount() == 200);
        for (uint64_t i = 0; i < 200; ++i)
            Require(Equal(nestedExpanded[static_cast<size_t>(i)], Event(i + 1, (i % 4 < 2) ? 10 : i % 4 + 20)));
        TracePathValidator invalid;
        auto marker = Event(1, 0);
        marker.type = TraceBasicBlockEventType::Repeat;
        Require(!invalid.Accept(marker));
        TracePathValidator overflow;
        Require(overflow.Accept(Event(UINT64_MAX - 1, 1)));
        marker = {}; marker.type = TraceBasicBlockEventType::Repeat;
        marker.source = 1; marker.sourceInstruction = 2; marker.target = 1;
        marker.sequence = UINT64_MAX; marker.threadId = 7; marker.codeVersion = UINT32_MAX;
        Require(!overflow.Accept(marker));
        std::cout << "bounded path codec: 33 widths, branch/stride/gap/unknown/exception/tail/prefix/overflow passed\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << "\n"; return 1; }
}
