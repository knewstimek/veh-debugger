#include "tools_common.h"
#include <iomanip>
#include <sstream>

namespace veh {

constexpr unsigned kLite = 1, kInteractive = 2, kCapture = 4, kFullProfile = ~0u;

uint32_t JsonUint32(const json& args, const char* key, uint32_t defaultVal) {
	if (!args.contains(key)) return defaultVal;
	const auto& v = args[key];
	if (v.is_number()) return v.get<uint32_t>();
	if (v.is_string()) {
		const auto& s = v.get<std::string>();
		if (s.empty() || s[0] == '-') return defaultVal;
		try {
			return static_cast<uint32_t>(std::stoul(s, nullptr, 0));
		} catch (...) {
			return defaultVal;
		}
	}
	return defaultVal;
}

int JsonInt(const json& args, const char* key, int defaultVal) {
	if (!args.contains(key)) return defaultVal;
	const auto& v = args[key];
	if (v.is_number()) return v.get<int>();
	if (v.is_string()) {
		try {
			return std::stoi(v.get<std::string>(), nullptr, 0);
		} catch (...) {
			return defaultVal;
		}
	}
	return defaultVal;
}

bool JsonBool(const json& args, const char* key, bool defaultVal) {
	if (!args.contains(key)) return defaultVal;
	const auto& v = args[key];
	if (v.is_boolean()) return v.get<bool>();
	if (v.is_string()) {
		auto s = v.get<std::string>();
		return s == "true" || s == "1";
	}
	if (v.is_number_integer()) return v.get<int>() != 0;
	if (v.is_number()) return v.get<double>() != 0.0;
	return defaultVal;
}

std::string HexAddr(uint64_t value) {
	char buf[24];
	snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(value));
	return buf;
}

// Profile name -> ToolDef::profiles mask; 0 for an unknown profile
unsigned ProfileMask(const std::string& profile) {
	if (profile == "lite") return kLite;
	if (profile == "interactive") return kInteractive;
	if (profile == "capture") return kCapture;
	if (profile == "full") return kFullProfile;
	return 0;
}

} // namespace veh
