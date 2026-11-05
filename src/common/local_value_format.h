#pragma once
#include <cstdint>
#include <optional>
#include <string>

namespace veh {
struct LocalValueBytes {
    std::string text;
    std::string hex;
    bool truncated;
};

// Inputs come from a validated EnumLocals reply. Bytes are shown in backend
// order; an incomplete scalar must never be zero-padded into a complete value.
inline std::optional<LocalValueBytes> FormatLocalValueBytes(
    const uint8_t* data,uint32_t captured,uint32_t declared)
{
    if(!captured)return std::nullopt;
    const bool scalar_width=declared==1||declared==2||declared==4||declared==8;
    if(scalar_width&&captured>=declared)return std::nullopt;
    LocalValueBytes out={};
    constexpr char digits[]="0123456789ABCDEF";
    for(uint32_t i=0;i<captured;++i) {
        if(i)out.text+=' ';
        const char hi=digits[data[i]>>4],lo=digits[data[i]&15];
        out.text+=hi;out.text+=lo;out.hex+=hi;out.hex+=lo;
    }
    out.truncated=declared&&captured<declared;
    if(out.truncated)out.text+=" ("+std::to_string(captured)+"/"+std::to_string(declared)+" bytes)";
    else if(!declared)out.text+=" ("+std::to_string(captured)+" bytes; size unknown)";
    return out;
}
} // namespace veh
