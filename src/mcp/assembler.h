#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace veh {

struct AssembleResult {
	bool ok = false;
	std::vector<uint8_t> bytes;
	std::string error;      // asmjit/asmtk error text
	int errorLine = 0;      // 1-based line of the failing instruction, 0 when not line-specific
};

// Assembles Intel-syntax x86/x64 text as if placed at `address`, so relative
// branches and rip-relative operands resolve against it. Instructions are
// separated by newlines or ';'; labels ("loop:") may be referenced across lines.
AssembleResult AssembleText(const std::string& text, uint64_t address, bool x64);

} // namespace veh
