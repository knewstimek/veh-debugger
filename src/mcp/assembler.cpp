#include "assembler.h"

#include <asmjit/x86.h>
#include <asmtk/asmtk.h>

namespace veh {

// "prefetchw byte ptr [rbx]" -> "prefetchw [rbx]". asmjit rejects a size on operands
// it sizes itself (prefetch, lea, ...), while disassemblers always print one.
static std::string StripSizeSpecifiers(const std::string& line) {
	static const char* kSizes[] = {"byte", "word", "dword", "fword", "qword", "tword",
		"oword", "xmmword", "ymmword", "zmmword"};
	std::string out = line;
	for (const char* size : kSizes) {
		const std::string token = std::string(size) + " ptr ";
		for (size_t pos = out.find(token); pos != std::string::npos; pos = out.find(token, pos)) {
			const bool wordStart = pos == 0 || out[pos - 1] == ' ' || out[pos - 1] == ',';
			if (wordStart) out.erase(pos, token.size());
			else pos += token.size();
		}
	}
	return out;
}

AssembleResult AssembleText(const std::string& text, uint64_t address, bool x64) {
	using namespace asmjit;
	AssembleResult result;

	CodeHolder code;
	if (Error err = code.init(Environment(x64 ? Arch::kX64 : Arch::kX86), address); err != kErrorOk) {
		result.error = DebugUtils::error_as_string(err);
		return result;
	}
	x86::Assembler assembler(&code);
	asmtk::AsmParser parser(&assembler);

	// asmtk treats ';' as a comment, so split on it as well as on newlines, and
	// feed one line at a time to report which instruction failed.
	int lineNumber = 0;
	size_t start = 0;
	while (start <= text.size()) {
		size_t end = text.find_first_of(";\n", start);
		if (end == std::string::npos) end = text.size();
		std::string line = text.substr(start, end - start);
		++lineNumber;
		if (line.find_first_not_of(" \t\r") != std::string::npos) {
			Error err = parser.parse(line.c_str(), line.size());
			if (err != kErrorOk && line.find(" ptr ") != std::string::npos) {
				const std::string unsized = StripSizeSpecifiers(line);
				if (parser.parse(unsized.c_str(), unsized.size()) == kErrorOk) err = kErrorOk;
			}
			if (err != kErrorOk) {
				result.error = DebugUtils::error_as_string(err);
				result.errorLine = lineNumber;
				return result;
			}
		}
		start = end + 1;
	}

	Error err = code.flatten();
	if (err == kErrorOk) err = code.resolve_cross_section_fixups();
	if (err == kErrorOk && code.has_unresolved_fixups()) err = Error::kInvalidLabel;
	if (err == kErrorOk) err = code.relocate_to_base(address);
	if (err != kErrorOk) {
		result.error = DebugUtils::error_as_string(err);
		return result;
	}

	const CodeBuffer& buffer = code.text_section()->buffer();
	result.bytes.assign(buffer.data(), buffer.data() + buffer.size());
	result.ok = true;
	return result;
}

} // namespace veh
