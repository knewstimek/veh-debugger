#pragma once
#include <windows.h>
#include <intrin.h>
#include <immintrin.h>
#include <cstdint>
#include <cstring>

// Called on the traced thread with its live exception CONTEXT. Never pass a
// standalone CONTEXT copy to the XState APIs: its extension is not copied.
namespace veh {
inline bool TraceXStateBytes(const CONTEXT* context, DWORD feature,
                            size_t offset, void* output, size_t size) {
    __try {
        if ((context->ContextFlags & CONTEXT_XSTATE) != CONTEXT_XSTATE) return false;
        DWORD64 present = 0;
        if (!GetXStateFeaturesMask(const_cast<CONTEXT*>(context), &present)) return false;
        if (!(present & (1ull << feature))) {
            memset(output, 0, size); // Architectural INIT state, not unavailable state.
            return true;
        }
        DWORD bytes = 0;
        const auto* data = static_cast<const uint8_t*>(
            LocateXStateFeature(const_cast<CONTEXT*>(context), feature, &bytes));
        if (!data || offset > bytes || size > bytes - offset) return false;
        memcpy(output, data + offset, size);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

inline bool TraceVectorBytes(const CONTEXT* context, uint8_t reg,
                             uint8_t size, uint8_t* output) {
    if (!context || !size || size > 64 || reg >= 32) return false;
    memset(output, 0, size);
    if (reg >= 16) return TraceXStateBytes(context, 7, (reg - 16) * 64, output, size);
#ifdef _WIN64
    if ((context->ContextFlags & CONTEXT_FLOATING_POINT) != CONTEXT_FLOATING_POINT) return false;
    memcpy(output, &context->Xmm0 + reg, size < 16 ? size : 16);
#else
    if (reg >= 8 || (context->ContextFlags & CONTEXT_EXTENDED_REGISTERS) != CONTEXT_EXTENDED_REGISTERS) return false;
    memcpy(output, context->ExtendedRegisters + 160 + reg * 16, size < 16 ? size : 16);
#endif
    if (size > 16 && !TraceXStateBytes(context, 2, reg * 16, output + 16,
                                     size < 32 ? size - 16 : 16)) return false;
    if (size > 32 && !TraceXStateBytes(context, 6, reg * 32, output + 32, size - 32)) return false;
    return true;
}

inline bool TraceMaskBits(const CONTEXT* context, uint8_t reg, uint64_t& bits) {
    return reg < 8 && TraceXStateBytes(context, 5, reg * 8, &bits, sizeof(bits));
}

inline bool TraceSegmentBase(const CONTEXT* context, uint8_t segment, uint64_t& base) {
    base = 0;
    if (!segment) return true;
    __try {
#ifdef _WIN64
        // These instructions read the actual thread bases, including WRFSBASE/
        // WRGSBASE changes when the OS enables FSGSBASE.
        base = segment == 1 ? _readfsbase_u64() : _readgsbase_u64();
        return true;
#else
        const DWORD selector = segment == 1 ? context->SegFs : context->SegGs;
        if (!selector) return true;
        LDT_ENTRY entry{};
        if (!GetThreadSelectorEntry(GetCurrentThread(), selector, &entry)) return false;
        base = entry.BaseLow | (uint64_t(entry.HighWord.Bytes.BaseMid) << 16) |
               (uint64_t(entry.HighWord.Bytes.BaseHi) << 24);
        return true;
#endif
    } __except (EXCEPTION_EXECUTE_HANDLER) {
#ifdef _WIN64
        // On Windows without FSGSBASE, native GS is the TEB. A null FS selector
        // has zero base; do not guess a non-null selector's base.
        if (segment == 2) { base = reinterpret_cast<uint64_t>(NtCurrentTeb()); return true; }
        if (context->SegFs == 0) return true;
#endif
        return false;
    }
}
} // namespace veh
