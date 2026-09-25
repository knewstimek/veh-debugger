#include "mcp_server.h"
#include "tools_common.h"
#include "batch_executor.h"
#include "trace_basic_blocks_tool.h"
#include "assembler.h"
#include "adapter/disassembler.h"
#include "common/logger.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")

namespace veh {

json McpServer::ToolReadMemory(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	std::string addrStr = args.value("address", "");
	int size = JsonInt(args, "size", 64);
	if (addrStr.empty()) return {{"error", "address is required"}};
	if (size <= 0 || size > 1048576) return {{"error", "size must be 1-1048576"}};

	uint64_t addr;
	if (!ParseAddress(addrStr, addr)) {
		return {{"error", "invalid address format"}};
	}

	auto data = session_.ReadMemory(addr, static_cast<uint32_t>(size));
	if (data.empty()) {
		return {{"error", "Memory read failed (address may be invalid or inaccessible)"}};
	}

	std::ostringstream oss;
	for (size_t i = 0; i < data.size(); i++) {
		if (i > 0 && i % 16 == 0) oss << "\n";
		else if (i > 0) oss << " ";
		oss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
	}

	char addrBuf[20];
	snprintf(addrBuf, sizeof(addrBuf), "0x%llX", addr);

	return {{"address", addrBuf}, {"size", data.size()}, {"hex", oss.str()}};
}

json McpServer::ToolReadPointerChain(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	std::string baseStr = args.value("base", "");
	if (baseStr.empty()) baseStr = args.value("address", "");  // alias
	if (baseStr.empty()) return {{"error", "base is required"}};

	uint64_t cur;
	if (!ParseAddress(baseStr, cur)) return {{"error", "invalid base address format"}};

	if (!args.contains("offsets") || !args["offsets"].is_array())
		return {{"error", "offsets array is required (e.g. [\"0x2c\",\"0x1c\",\"0x10\"])"}};

	std::vector<int64_t> offsets;
	for (auto& o : args["offsets"]) {
		if (o.is_string()) {
			try { offsets.push_back((int64_t)std::stoll(o.get<std::string>(), nullptr, 0)); }
			catch (...) { return {{"error", "invalid offset: " + o.get<std::string>()}}; }
		} else if (o.is_number_integer()) {
			offsets.push_back(o.get<int64_t>());
		} else {
			return {{"error", "offsets must be hex strings or integers"}};
		}
	}
	if (offsets.empty()) return {{"error", "offsets must not be empty"}};
	if (offsets.size() > 64) return {{"error", "too many offsets (max 64 hops)"}};

	bool derefFinal = JsonBool(args, "derefFinal", true);
	int readSize = JsonInt(args, "size", 0);

	// 포인터 크기 판정 (QUERY 권한만 필요). deref 자체는 IPC ReadMemory(DLL 인-프로세스)로
	// 처리 -- targetProcess_ 핸들에 VM_READ가 없어도 동작.
	BOOL isWow64 = FALSE;
	if (HANDLE hProc = session_.GetTargetProcess()) IsWow64Process(hProc, &isWow64);
	int ptrSize = isWow64 ? 4 : 8;

	json steps = json::array();
	for (size_t i = 0; i < offsets.size(); i++) {
		int64_t off = offsets[i];
		uint64_t target = cur + (uint64_t)off;
		// 오버플로우/언더플로우 가드: wrap 되면 잘못된 주소이므로 거부
		if ((off >= 0 && target < cur) || (off < 0 && target > cur)) {
			char ob[20]; snprintf(ob, sizeof(ob), "0x%llX", (unsigned long long)cur);
			return {{"error", "address overflow at step " + std::to_string(i) + " (base " + ob + ")"},
			        {"steps", steps}, {"failedStep", (int)i}};
		}
		char tbuf[20]; snprintf(tbuf, sizeof(tbuf), "0x%llX", target);
		bool doDeref = derefFinal || (i + 1 < offsets.size());
		if (!doDeref) {
			cur = target;  // 마지막 오프셋: deref 없이 주소 자체가 결과
			steps.push_back({{"deref_at", tbuf}, {"value", nullptr}, {"note", "final (no deref)"}});
			break;
		}
		auto bytes = session_.ReadMemory(target, (uint32_t)ptrSize);
		if (bytes.size() < (size_t)ptrSize) {
			return {{"error", "pointer read failed at step " + std::to_string(i) + " (address " + tbuf + ")"},
			        {"steps", steps}, {"failedStep", (int)i}};
		}
		uint64_t val = 0;
		memcpy(&val, bytes.data(), ptrSize);
		char vbuf[20]; snprintf(vbuf, sizeof(vbuf), "0x%llX", val);
		steps.push_back({{"deref_at", tbuf}, {"value", vbuf}});
		cur = val;
	}

	char rbuf[20]; snprintf(rbuf, sizeof(rbuf), "0x%llX", cur);
	json ret = {{"success", true}, {"resolved", rbuf}, {"steps", steps}, {"pointerSize", ptrSize}};

	if (readSize > 0) {
		if (readSize > 4096) readSize = 4096;
		auto data = session_.ReadMemory(cur, (uint32_t)readSize);
		if (!data.empty()) {
			std::ostringstream oss;
			for (size_t i = 0; i < data.size(); i++) {
				if (i > 0 && i % 16 == 0) oss << "\n";
				else if (i > 0) oss << " ";
				oss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
			}
			ret["hex"] = oss.str();
			ret["bytesRead"] = (uint64_t)data.size();
			uint64_t iv = 0; memcpy(&iv, data.data(), data.size() < 8 ? data.size() : 8);
			char ib[20]; snprintf(ib, sizeof(ib), "0x%llX", iv);
			ret["value"] = ib;
		} else {
			ret["readError"] = "final read failed (resolved address inaccessible)";
		}
	}
	return ret;
}

// Helper: parse hex string to bytes
static bool ParseHexBytes(const std::string& hexStr, std::vector<uint8_t>& out) {
	std::string clean;
	for (char c : hexStr) {
		if (std::isxdigit(c)) clean += c;
	}
	if (clean.size() % 2 != 0) return false;
	out.clear();
	for (size_t i = 0; i < clean.size(); i += 2) {
		out.push_back(static_cast<uint8_t>(std::stoi(clean.substr(i, 2), nullptr, 16)));
	}
	return true;
}

json McpServer::ToolWriteMemory(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	// Batch mode: patches array [{address, data}, ...]
	if (args.contains("patches") && args["patches"].is_array()) {
		const auto& patches = args["patches"];
		if (patches.size() > 1000) return {{"error", "Too many patches (max 1000)"}};
		int succeeded = 0, failed = 0;
		json errors = json::array();
		for (const auto& patch : patches) {
			std::string pAddr = patch.value("address", "");
			std::string pData = patch.value("data", "");
			uint64_t addr;
			if (pAddr.empty() || !ParseAddress(pAddr, addr)) {
				failed++;
				errors.push_back({{"address", pAddr}, {"error", "invalid address"}});
				continue;
			}
			std::vector<uint8_t> bytes;
			if (!ParseHexBytes(pData, bytes) || bytes.empty()) {
				failed++;
				errors.push_back({{"address", pAddr}, {"error", "invalid hex data"}});
				continue;
			}
			if (session_.WriteMemory(addr, bytes.data(), static_cast<uint32_t>(bytes.size()))) {
				succeeded++;
			} else {
				failed++;
				errors.push_back({{"address", pAddr}, {"error", "write failed"}});
			}
		}
		json ret = {{"success", failed == 0}, {"succeeded", succeeded}, {"failed", failed}};
		if (!errors.empty()) ret["errors"] = errors;
		return ret;
	}

	// Single mode
	std::string addrStr = args.value("address", "");
	std::string dataHex = args.value("data", "");
	if (addrStr.empty()) return {{"error", "address is required"}};
	if (dataHex.empty()) return {{"error", "data is required (hex string)"}};

	uint64_t addr;
	if (!ParseAddress(addrStr, addr)) {
		return {{"error", "invalid address format"}};
	}

	std::vector<uint8_t> bytes;
	if (!ParseHexBytes(dataHex, bytes)) return {{"error", "Invalid hex string"}};
	if (bytes.size() > 1048576) {
		return {{"error", "data too large (max 1MB)"}};
	}

	if (!session_.WriteMemory(addr, bytes.data(), static_cast<uint32_t>(bytes.size()))) {
		return {{"error", "Memory write failed (address may be invalid, read-only, or inaccessible)"}};
	}

	return {{"success", true}, {"bytesWritten", bytes.size()}};
}

json McpServer::ToolDumpMemory(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	std::string addrStr = args.value("address", "");
	int size = JsonInt(args, "size", 4096);
	std::string outputPath = args.value("output_path", "");
	if (addrStr.empty()) return {{"error", "address is required"}};
	if (outputPath.empty()) return {{"error", "output_path is required"}};
	if (size <= 0 || size > 64 * 1024 * 1024) return {{"error", "size must be 1-67108864 (64MB)"}};

	uint64_t addr;
	if (!ParseAddress(addrStr, addr)) {
		return {{"error", "invalid address format"}};
	}

	FILE* fp = fopen(outputPath.c_str(), "wb");
	if (!fp) {
		return {{"error", "Cannot open output file: " + outputPath}};
	}

	const uint32_t chunkSize = 1024 * 1024;
	uint64_t totalWritten = 0;
	uint64_t remaining = static_cast<uint64_t>(size);
	uint64_t currentAddr = addr;

	while (remaining > 0) {
		uint32_t toRead = static_cast<uint32_t>((remaining > chunkSize) ? chunkSize : remaining);
		auto data = session_.ReadMemory(currentAddr, toRead);
		if (data.empty()) {
			fclose(fp);
			if (totalWritten > 0) {
				return {{"partial", true}, {"bytesWritten", totalWritten},
				        {"error", "Memory read failed at offset " + std::to_string(totalWritten)}};
			}
			return {{"error", "Memory read failed at starting address"}};
		}

		fwrite(data.data(), 1, data.size(), fp);
		totalWritten += data.size();
		currentAddr += data.size();
		if (data.size() > remaining) break;
		remaining -= data.size();
	}

	fclose(fp);
	char addrBuf[20];
	snprintf(addrBuf, sizeof(addrBuf), "0x%llX", addr);

	// Verify file: size + SHA256 checksum
	FILE* verify = fopen(outputPath.c_str(), "rb");
	uint64_t fileSize = 0;
	std::string sha256hex;
	if (verify) {
		HCRYPTPROV hProv = 0; HCRYPTHASH hHash = 0;
		_fseeki64(verify, 0, SEEK_END);
		fileSize = _ftelli64(verify);
		_fseeki64(verify, 0, SEEK_SET);

		if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
			if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
				uint8_t buf[65536];
				size_t bytesRead;
				while ((bytesRead = fread(buf, 1, sizeof(buf), verify)) > 0) {
					CryptHashData(hHash, buf, static_cast<DWORD>(bytesRead), 0);
				}
				DWORD hashLen = 32; uint8_t hash[32];
				if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
					char hex[65];
					for (DWORD i = 0; i < hashLen; i++) snprintf(hex + i * 2, 3, "%02x", hash[i]);
					sha256hex = hex;
				}
				CryptDestroyHash(hHash);
			}
			CryptReleaseContext(hProv, 0);
		}
		fclose(verify);
	}

	json ret = {{"success", true}, {"address", addrBuf}, {"size", totalWritten},
	            {"output_path", outputPath}, {"fileSize", fileSize},
	            {"verified", fileSize == totalWritten}};
	if (!sha256hex.empty()) ret["sha256"] = sha256hex;
	return ret;
}

struct ProtectionName {
	const char* name;
	uint32_t value;
};

static constexpr ProtectionName kProtectionNames[] = {
	{"none", PAGE_NOACCESS},
	{"r", PAGE_READONLY},
	{"rw", PAGE_READWRITE},
	{"rc", PAGE_WRITECOPY},
	{"x", PAGE_EXECUTE},
	{"rx", PAGE_EXECUTE_READ},
	{"rwx", PAGE_EXECUTE_READWRITE},
	{"rxc", PAGE_EXECUTE_WRITECOPY},
};

static bool ParseProtectText(const std::string& text, uint32_t& protect) {
	const size_t suffix = text.find('+');
	const std::string base = text.substr(0, suffix);
	protect = 0;
	for (const auto& entry : kProtectionNames) {
		if (base == entry.name) {
			protect = entry.value;
			break;
		}
	}
	if (protect == 0) return false;
	if (suffix == std::string::npos) return true;

	bool guard = false;
	bool nocache = false;
	size_t pos = suffix + 1;
	while (pos <= text.size()) {
		const size_t next = text.find('+', pos);
		const std::string flag = text.substr(pos, next - pos);
		if (flag == "guard" && !guard) {
			protect |= PAGE_GUARD;
			guard = true;
		} else if (flag == "nocache" && !nocache) {
			protect |= PAGE_NOCACHE;
			nocache = true;
		} else {
			return false;
		}
		if (next == std::string::npos) break;
		pos = next + 1;
	}
	return true;
}

static std::string ProtectText(uint32_t protect) {
	std::string text;
	for (const auto& entry : kProtectionNames) {
		if ((protect & 0xFF) == entry.value) {
			text = entry.name;
			break;
		}
	}
	if (text.empty()) text = protect ? "?" : "";
	if (protect & PAGE_GUARD) text += "+guard";
	if (protect & PAGE_NOCACHE) text += "+nocache";
	return text;
}

json McpServer::ToolAllocateMemory(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	int size = JsonInt(args, "size", 4096);
	std::string protStr = args.value("protection", "rwx");
	if (size <= 0 || size > 64 * 1024 * 1024) return {{"error", "size must be 1-67108864"}};

	uint32_t protection = 0;
	if (!ParseProtectText(protStr, protection)) return {{"error", "invalid protection"}};

	uint64_t addr = session_.AllocateMemory(static_cast<uint32_t>(size), protection);
	if (addr == 0) {
		return {{"error", "VirtualAlloc failed in target process"}};
	}

	char buf[20];
	snprintf(buf, sizeof(buf), "0x%llX", addr);
	return {{"success", true}, {"address", buf}, {"size", size},
		{"protection", ProtectText(protection)}};
}

json McpServer::ToolProtectMemory(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	uint64_t address = 0;
	if (!ParseAddress(args.value("address", ""), address))
		return {{"error", "invalid address format"}};
	if (!args.contains("size") || !args["size"].is_number_integer())
		return {{"error", "size must be a positive integer"}};
	uint64_t size = 0;
	if (args["size"].is_number_unsigned()) {
		size = args["size"].get<uint64_t>();
	} else {
		const int64_t signedSize = args["size"].get<int64_t>();
		if (signedSize > 0) size = static_cast<uint64_t>(signedSize);
	}
	if (size == 0) return {{"error", "size must be a positive integer"}};

	const std::string protectionText = args.value("protection", "");
	uint32_t protection = 0;
	if (!ParseProtectText(protectionText, protection))
		return {{"error", "invalid protection"}};

	const std::string methodText = args.value("method", "api");
	ProtectMemoryMethod method;
	if (methodText == "api") method = ProtectMemoryMethod::Api;
	else if (methodText == "nt") method = ProtectMemoryMethod::Nt;
	else if (methodText == "syscall") method = ProtectMemoryMethod::Syscall;
	else return {{"error", "method must be api, nt, or syscall"}};

	auto result = session_.ProtectMemory(address, size, protection, method);
	auto methodName = [](ProtectMemoryMethod value) {
		switch (value) {
		case ProtectMemoryMethod::Api: return "api";
		case ProtectMemoryMethod::Nt: return "nt";
		case ProtectMemoryMethod::Syscall: return "syscall";
		default: return "unknown";
		}
	};
	if (!result.ok) {
		char code[16];
		snprintf(code, sizeof(code), "0x%08X", result.errorCode);
		const std::string kind = result.method == ProtectMemoryMethod::Api ? "Win32" : "NTSTATUS";
		return {{"error", std::string("memory protection failed (") + kind + " " + code + ")"},
			{"code", code}, {"method", methodName(result.method)}};
	}

	return {{"address", HexAddr(address)}, {"size", size},
		{"protection", ProtectText(protection)}, {"old_protection", ProtectText(result.oldProtection)},
		{"method", methodName(result.method)}};
}

bool McpServer::ParseRangeArgs(const json& args, uint64_t& start, uint64_t& end, std::string& error) {
	start = 0;
	end = 0;
	std::string module = args.value("module", "");
	if (!module.empty()) {
		std::string lower = module;
		std::transform(lower.begin(), lower.end(), lower.begin(), [](char c) { return (char)::tolower((unsigned char)c); });
		for (auto& m : session_.GetModules()) {
			std::string name = m.name;
			std::transform(name.begin(), name.end(), name.begin(), [](char c) { return (char)::tolower((unsigned char)c); });
			if (name == lower) { start = m.baseAddress; end = m.baseAddress + m.size; break; }
		}
		if (!end) { error = "module not found: " + module; return false; }
	}
	std::string s = args.value("start", "");
	std::string e = args.value("end", "");
	if (!s.empty() && !ParseAddress(s, start)) { error = "invalid start address"; return false; }
	if (!e.empty() && !ParseAddress(e, end)) { error = "invalid end address"; return false; }
	if (end && end <= start) { error = "end must be greater than start"; return false; }
	return true;
}

std::string McpServer::ModuleLocation(uint64_t address, const std::vector<ModuleEntry>& modules) {
	for (auto& m : modules) {
		if (address >= m.baseAddress && address < m.baseAddress + m.size) {
			char buf[24];
			snprintf(buf, sizeof(buf), "+0x%llX", static_cast<unsigned long long>(address - m.baseAddress));
			return m.name + buf;
		}
	}
	return {};
}

json McpServer::ToolMemoryMap(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};
	uint64_t start, end;
	std::string error;
	if (!ParseRangeArgs(args, start, end, error)) return {{"error", error}};
	uint32_t maxRegions = JsonUint32(args, "max_regions", 200);
	if (maxRegions == 0 || maxRegions > 4096) maxRegions = 200;

	auto map = session_.QueryMemoryMap(start, end, maxRegions, JsonBool(args, "include_free", false));
	if (!map.ok) return {{"error", "memory map query failed"}};

	auto modules = session_.GetModules();
	json regions = json::array();
	for (auto& r : map.regions) {
		json entry = {{"base", HexAddr(r.baseAddress)}, {"size", HexAddr(r.regionSize)}};
		entry["state"] = r.state == MEM_COMMIT ? "commit" : r.state == MEM_RESERVE ? "reserve" : "free";
		if (r.state != MEM_FREE) {
			if (r.state == MEM_COMMIT) entry["protect"] = ProtectText(r.protect);
			entry["type"] = r.type == MEM_IMAGE ? "image" : r.type == MEM_MAPPED ? "mapped" : "private";
			if (r.allocationBase != r.baseAddress) entry["allocationBase"] = HexAddr(r.allocationBase);
			if (r.type == MEM_IMAGE) {
				auto location = ModuleLocation(r.baseAddress, modules);
				if (!location.empty()) entry["module"] = location;
			}
		}
		regions.push_back(std::move(entry));
	}
	json result = {{"regions", regions}, {"count", regions.size()}, {"truncated", map.nextAddress != 0}};
	if (map.nextAddress) result["next_start"] = HexAddr(map.nextAddress);
	return result;
}

// Builds the byte pattern and compare mask from one of: pattern (AOB), string, value.
static bool BuildSearchPattern(const json& args, bool is64, std::vector<uint8_t>& pattern,
	std::vector<uint8_t>& mask, std::string& error) {
	const int kinds = (args.contains("pattern") ? 1 : 0) + (args.contains("string") ? 1 : 0)
		+ (args.contains("value") ? 1 : 0);
	if (kinds != 1) { error = "provide exactly one of pattern, string, value"; return false; }

	if (args.contains("pattern")) {
		std::string text = args["pattern"].is_string() ? args["pattern"].get<std::string>() : "";
		std::vector<std::string> tokens;
		std::string cur;
		for (char c : text) {
			if (c == ' ' || c == ',' || c == '\t') {
				if (!cur.empty()) { tokens.push_back(cur); cur.clear(); }
			} else {
				cur += c;
			}
		}
		if (!cur.empty()) tokens.push_back(cur);
		// "488B??C3" without separators: split into byte pairs.
		if (tokens.size() == 1 && tokens[0].size() > 2 && tokens[0].size() % 2 == 0) {
			std::string joined = tokens[0];
			tokens.clear();
			for (size_t i = 0; i < joined.size(); i += 2) tokens.push_back(joined.substr(i, 2));
		}
		auto nibble = [](char c, uint8_t& v) {
			if (c >= '0' && c <= '9') { v = uint8_t(c - '0'); return true; }
			c = (char)::tolower((unsigned char)c);
			if (c >= 'a' && c <= 'f') { v = uint8_t(c - 'a' + 10); return true; }
			return false;
		};
		for (auto& t : tokens) {
			if (t == "?" || t == "??") { pattern.push_back(0); mask.push_back(0); continue; }
			if (t.size() != 2) { error = "invalid pattern token: " + t; return false; }
			uint8_t hi = 0, lo = 0, m = 0;
			if (t[0] != '?') { if (!nibble(t[0], hi)) { error = "invalid pattern token: " + t; return false; } m |= 0xF0; }
			if (t[1] != '?') { if (!nibble(t[1], lo)) { error = "invalid pattern token: " + t; return false; } m |= 0x0F; }
			pattern.push_back(uint8_t((hi << 4) | lo));
			mask.push_back(m);
		}
	} else if (args.contains("string")) {
		std::string text = args["string"].is_string() ? args["string"].get<std::string>() : "";
		std::string encoding = args.value("encoding", "ascii");
		if (encoding == "utf16") {
			int wlen = MultiByteToWideChar(CP_UTF8, 0, text.data(), (int)text.size(), nullptr, 0);
			std::wstring wide(wlen, L'\0');
			MultiByteToWideChar(CP_UTF8, 0, text.data(), (int)text.size(), wide.data(), wlen);
			auto* bytes = reinterpret_cast<const uint8_t*>(wide.data());
			pattern.assign(bytes, bytes + wide.size() * sizeof(wchar_t));
		} else if (encoding == "ascii" || encoding == "utf8") {
			pattern.assign(text.begin(), text.end());
		} else {
			error = "encoding must be ascii, utf8, or utf16";
			return false;
		}
		mask.assign(pattern.size(), 0xFF);
	} else {
		std::string type = args.value("value_type", "i32");
		const json& v = args["value"];
		auto put = [&](const void* p, size_t size) {
			auto* b = static_cast<const uint8_t*>(p);
			pattern.assign(b, b + size);
		};
		try {
			if (type == "f32" || type == "f64") {
				double d = v.is_string() ? std::stod(v.get<std::string>()) : v.get<double>();
				if (type == "f32") { float f = (float)d; put(&f, 4); } else put(&d, 8);
			} else {
				uint64_t raw = 0;
				if (v.is_string()) {
					std::string s = v.get<std::string>();
					raw = (!s.empty() && s[0] == '-') ? (uint64_t)std::stoll(s, nullptr, 0) : std::stoull(s, nullptr, 0);
				} else if (v.is_number_unsigned()) {
					raw = v.get<uint64_t>();
				} else {
					raw = (uint64_t)v.get<int64_t>();
				}
				size_t size = 0;
				if (type == "i8" || type == "u8") size = 1;
				else if (type == "i16" || type == "u16") size = 2;
				else if (type == "i32" || type == "u32") size = 4;
				else if (type == "i64" || type == "u64") size = 8;
				else if (type == "ptr") size = is64 ? 8 : 4;
				else { error = "value_type must be i8/u8/i16/u16/i32/u32/i64/u64/f32/f64/ptr"; return false; }
				put(&raw, size);  // little-endian low bytes
			}
		} catch (...) {
			error = "invalid value";
			return false;
		}
		mask.assign(pattern.size(), 0xFF);
	}
	if (pattern.empty()) { error = "empty pattern"; return false; }
	if (pattern.size() > 4096) { error = "pattern longer than 4096 bytes"; return false; }
	bool anyCompared = false;
	for (auto m : mask) anyCompared |= m != 0;
	if (!anyCompared) { error = "pattern is all wildcards"; return false; }
	return true;
}

static bool ParseRegionFilter(const json& args, const char* key, RegionFilter& out,
	RegionFilter defaultFilter = RegionFilter::Any) {
	out = defaultFilter;
	if (!args.contains(key) || args[key].is_null()) return true;
	if (args[key].is_string() && args[key].get<std::string>() == "any") {
		out = RegionFilter::Any;
		return true;
	}
	if (!args[key].is_boolean()) return false;
	out = args[key].get<bool>() ? RegionFilter::Require : RegionFilter::Exclude;
	return true;
}

json McpServer::ToolSearchMemory(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	std::vector<uint8_t> pattern, mask;
	std::string error;
	BOOL isWow64 = FALSE;
	if (HANDLE hProc = session_.GetTargetProcess()) IsWow64Process(hProc, &isWow64);
	if (!BuildSearchPattern(args, !isWow64, pattern, mask, error)) return {{"error", error}};

	SearchMemoryRequest req{};
	if (!ParseRangeArgs(args, req.startAddress, req.endAddress, error)) return {{"error", error}};
	if (!ParseRegionFilter(args, "writable", req.writable) || !ParseRegionFilter(args, "executable", req.executable))
		return {{"error", "writable/executable must be true, false, or any"}};
	if (args.contains("type")) {
		json types = args["type"].is_array() ? args["type"] : json::array({args["type"]});
		for (auto& t : types) {
			std::string name = t.is_string() ? t.get<std::string>() : "";
			if (name == "image") req.typeMask |= kRegionTypeImage;
			else if (name == "private") req.typeMask |= kRegionTypePrivate;
			else if (name == "mapped") req.typeMask |= kRegionTypeMapped;
			else return {{"error", "type must be image, private, or mapped"}};
		}
	}
	req.alignment = JsonUint32(args, "alignment", 1);
	if (req.alignment == 0 || req.alignment > 4096) return {{"error", "alignment must be 1-4096"}};
	req.maxResults = JsonUint32(args, "max_results", 100);
	if (req.maxResults == 0 || req.maxResults > 10000) return {{"error", "max_results must be 1-10000"}};

	auto found = session_.SearchMemory(req, pattern, mask);
	if (!found.ok) return {{"error", "memory search failed (timeout or target error)"}};

	auto modules = session_.GetModules();
	json matches = json::array();
	for (uint64_t hit : found.matches) {
		json entry = {{"address", HexAddr(hit)}};
		auto location = ModuleLocation(hit, modules);
		if (!location.empty()) entry["location"] = location;
		matches.push_back(std::move(entry));
	}
	json result = {{"matches", matches}, {"count", matches.size()}, {"truncated", found.nextAddress != 0},
	               {"patternSize", pattern.size()}, {"regionsScanned", found.regionsScanned},
	               {"scannedBytes", found.scannedBytes}};
	if (found.nextAddress) result["next_start"] = HexAddr(found.nextAddress);
	return result;
}

static const char* ValueScanTypeName(ValueScanType type) {
	switch (type) {
	case ValueScanType::I8: return "i8";
	case ValueScanType::U8: return "u8";
	case ValueScanType::I16: return "i16";
	case ValueScanType::U16: return "u16";
	case ValueScanType::I32: return "i32";
	case ValueScanType::U32: return "u32";
	case ValueScanType::I64: return "i64";
	case ValueScanType::U64: return "u64";
	case ValueScanType::F32: return "f32";
	case ValueScanType::F64: return "f64";
	default: return "none";
	}
}

static bool ParseValueScanType(const std::string& name, ValueScanType& type, uint32_t& size) {
	if (name == "i8") { type = ValueScanType::I8; size = 1; }
	else if (name == "u8") { type = ValueScanType::U8; size = 1; }
	else if (name == "i16") { type = ValueScanType::I16; size = 2; }
	else if (name == "u16") { type = ValueScanType::U16; size = 2; }
	else if (name == "i32") { type = ValueScanType::I32; size = 4; }
	else if (name == "u32") { type = ValueScanType::U32; size = 4; }
	else if (name == "i64") { type = ValueScanType::I64; size = 8; }
	else if (name == "u64") { type = ValueScanType::U64; size = 8; }
	else if (name == "f32") { type = ValueScanType::F32; size = 4; }
	else if (name == "f64") { type = ValueScanType::F64; size = 8; }
	else return false;
	return true;
}

template <typename T>
static uint64_t ScanRaw(T value) {
	uint64_t raw = 0;
	memcpy(&raw, &value, sizeof(value));
	return raw;
}

static bool ParseScanRaw(const json& value, ValueScanType type, uint64_t& raw) {
	try {
		if (type == ValueScanType::F32 || type == ValueScanType::F64) {
			double number = value.is_string() ? std::stod(value.get<std::string>()) : value.get<double>();
			raw = type == ValueScanType::F32 ? ScanRaw(static_cast<float>(number)) : ScanRaw(number);
			return true;
		}
		const bool isSigned = type == ValueScanType::I8 || type == ValueScanType::I16
			|| type == ValueScanType::I32 || type == ValueScanType::I64;
		if (isSigned) {
			int64_t number = 0;
			if (value.is_string()) {
				size_t used = 0;
				number = std::stoll(value.get<std::string>(), &used, 0);
				if (used != value.get_ref<const std::string&>().size()) return false;
			} else number = value.get<int64_t>();
			int64_t low = (std::numeric_limits<int64_t>::min)();
			int64_t high = (std::numeric_limits<int64_t>::max)();
			if (type == ValueScanType::I8) { low = -128; high = 127; }
			else if (type == ValueScanType::I16) { low = -32768; high = 32767; }
			else if (type == ValueScanType::I32) {
				low = (std::numeric_limits<int32_t>::min)();
				high = (std::numeric_limits<int32_t>::max)();
			}
			if (number < low || number > high) return false;
			switch (type) {
			case ValueScanType::I8: raw = ScanRaw(static_cast<int8_t>(number)); break;
			case ValueScanType::I16: raw = ScanRaw(static_cast<int16_t>(number)); break;
			case ValueScanType::I32: raw = ScanRaw(static_cast<int32_t>(number)); break;
			default: raw = ScanRaw(number); break;
			}
			return true;
		}
		uint64_t number = 0;
		if (value.is_string()) {
			const std::string& text = value.get_ref<const std::string&>();
			if (!text.empty() && text[0] == '-') return false;
			size_t used = 0;
			number = std::stoull(text, &used, 0);
			if (used != text.size()) return false;
		} else {
			if (value.is_number_integer() && !value.is_number_unsigned() && value.get<int64_t>() < 0) return false;
			number = value.get<uint64_t>();
		}
		uint64_t high = (std::numeric_limits<uint64_t>::max)();
		if (type == ValueScanType::U8) high = 0xFF;
		else if (type == ValueScanType::U16) high = 0xFFFF;
		else if (type == ValueScanType::U32) high = 0xFFFFFFFFull;
		if (number > high) return false;
		switch (type) {
		case ValueScanType::U8: raw = ScanRaw(static_cast<uint8_t>(number)); break;
		case ValueScanType::U16: raw = ScanRaw(static_cast<uint16_t>(number)); break;
		case ValueScanType::U32: raw = ScanRaw(static_cast<uint32_t>(number)); break;
		default: raw = number; break;
		}
		return true;
	} catch (...) {
		return false;
	}
}

template <typename T>
static T RawScanValue(uint64_t raw) {
	T value{};
	memcpy(&value, &raw, sizeof(value));
	return value;
}

static json FormatScanValue(uint64_t raw, ValueScanType type) {
	switch (type) {
	case ValueScanType::I8: return RawScanValue<int8_t>(raw);
	case ValueScanType::U8: return RawScanValue<uint8_t>(raw);
	case ValueScanType::I16: return RawScanValue<int16_t>(raw);
	case ValueScanType::U16: return RawScanValue<uint16_t>(raw);
	case ValueScanType::I32: return RawScanValue<int32_t>(raw);
	case ValueScanType::U32: return RawScanValue<uint32_t>(raw);
	case ValueScanType::I64: return RawScanValue<int64_t>(raw);
	case ValueScanType::U64: return raw;
	case ValueScanType::F32: return RawScanValue<float>(raw);
	case ValueScanType::F64: return RawScanValue<double>(raw);
	default: return nullptr;
	}
}

static std::string ValueScanFailureText(ValueScanFailure failure) {
	switch (failure) {
	case ValueScanFailure::NoSession: return "no active value scan; run operation=first";
	case ValueScanFailure::InvalidRequest: return "invalid value scan request";
	case ValueScanFailure::TypeMismatch: return "value_type does not match the active value scan";
	case ValueScanFailure::TooManyResults:
		return "TooManyResults: more than 16M candidates; narrow the range or value";
	case ValueScanFailure::SnapshotTooLarge:
		return "SnapshotTooLarge: snapshot exceeds 512MB; specify module, start, or end";
	case ValueScanFailure::AllocationFailed: return "value scan storage allocation failed";
	default: return "value scan failed (timeout or target error)";
	}
}

json McpServer::ToolValueScan(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};
	const std::string operationName = args.value("operation", "");
	ValueScanRequest request{};
	if (operationName == "first") request.operation = ValueScanOperation::First;
	else if (operationName == "next") request.operation = ValueScanOperation::Next;
	else if (operationName == "results") request.operation = ValueScanOperation::Results;
	else if (operationName == "reset") request.operation = ValueScanOperation::Reset;
	else return {{"error", "operation must be first, next, results, or reset"}};

	request.maxResults = JsonUint32(args, "max_results", 20);
	if (request.maxResults == 0 || request.maxResults > 1000)
		return {{"error", "max_results must be 1-1000"}};
	if (request.operation == ValueScanOperation::Results && args.contains("offset")) {
		try {
			if (args["offset"].is_string()) {
				const std::string& text = args["offset"].get_ref<const std::string&>();
				if (!text.empty() && text[0] == '-') throw std::invalid_argument("negative");
				size_t used = 0;
				request.offset = std::stoull(text, &used, 0);
				if (used != text.size()) throw std::invalid_argument("trailing characters");
			} else {
				if (args["offset"].is_number_integer() && !args["offset"].is_number_unsigned()
					&& args["offset"].get<int64_t>() < 0) throw std::invalid_argument("negative");
				request.offset = args["offset"].get<uint64_t>();
			}
		} catch (...) { return {{"error", "offset must be a non-negative integer"}}; }
	}

	uint32_t valueSize = 4;
	if (!ParseValueScanType(args.value("value_type", "i32"), request.valueType, valueSize))
		return {{"error", "value_type must be i8/u8/i16/u16/i32/u32/i64/u64/f32/f64"}};

	if (request.operation == ValueScanOperation::First || request.operation == ValueScanOperation::Next) {
		const std::string compareName = args.value("compare", "exact");
		if (compareName == "exact") request.compare = ValueScanCompare::Exact;
		else if (compareName == "between") request.compare = ValueScanCompare::Between;
		else if (compareName == "greater") request.compare = ValueScanCompare::Greater;
		else if (compareName == "less") request.compare = ValueScanCompare::Less;
		else if (compareName == "unknown") request.compare = ValueScanCompare::Unknown;
		else if (compareName == "changed") request.compare = ValueScanCompare::Changed;
		else if (compareName == "unchanged") request.compare = ValueScanCompare::Unchanged;
		else if (compareName == "increased") request.compare = ValueScanCompare::Increased;
		else if (compareName == "decreased") request.compare = ValueScanCompare::Decreased;
		else if (compareName == "increased_by") request.compare = ValueScanCompare::IncreasedBy;
		else if (compareName == "decreased_by") request.compare = ValueScanCompare::DecreasedBy;
		else return {{"error", "invalid compare mode"}};

		if (request.operation == ValueScanOperation::First && request.compare > ValueScanCompare::Unknown)
			return {{"error", "changed/unchanged/increased/decreased/increased_by/decreased_by are only valid for next scans"}};
		const bool needsValue = request.compare == ValueScanCompare::Exact
			|| request.compare == ValueScanCompare::Between || request.compare == ValueScanCompare::Greater
			|| request.compare == ValueScanCompare::Less || request.compare == ValueScanCompare::IncreasedBy
			|| request.compare == ValueScanCompare::DecreasedBy;
		if (needsValue && (!args.contains("value") || !ParseScanRaw(args["value"], request.valueType, request.value)))
			return {{"error", "value is required and must fit value_type"}};
		if (request.compare == ValueScanCompare::Between
			&& (!args.contains("value2") || !ParseScanRaw(args["value2"], request.valueType, request.value2)))
			return {{"error", "value2 is required and must fit value_type for between"}};
	}

	if (request.operation == ValueScanOperation::First) {
		std::string error;
		if (!ParseRangeArgs(args, request.startAddress, request.endAddress, error)) return {{"error", error}};
		if (!ParseRegionFilter(args, "writable", request.writable, RegionFilter::Require)
			|| !ParseRegionFilter(args, "executable", request.executable))
			return {{"error", "writable/executable must be true, false, or any"}};
		if (args.contains("type")) {
			json types = args["type"].is_array() ? args["type"] : json::array({args["type"]});
			for (auto& item : types) {
				const std::string name = item.is_string() ? item.get<std::string>() : "";
				if (name == "image") request.typeMask |= kRegionTypeImage;
				else if (name == "private") request.typeMask |= kRegionTypePrivate;
				else if (name == "mapped") request.typeMask |= kRegionTypeMapped;
				else return {{"error", "type must be image, private, or mapped"}};
			}
		}
		request.alignment = JsonUint32(args, "alignment", valueSize);
		if (request.alignment == 0 || request.alignment > 4096)
			return {{"error", "alignment must be 1-4096"}};
	} else {
		request.alignment = valueSize;
	}

	auto scan = session_.ValueScan(request);
	if (!scan.ok) return {{"error", ValueScanFailureText(scan.failure)}};
	auto modules = session_.GetModules();
	json entries = json::array();
	for (const auto& item : scan.entries) {
		json entry = {{"address", HexAddr(item.address)}, {"value", FormatScanValue(item.value, scan.valueType)}};
		auto location = ModuleLocation(item.address, modules);
		if (!location.empty()) entry["location"] = location;
		entries.push_back(std::move(entry));
	}
	const char* mode = scan.mode == ValueScanMode::List ? "list"
		: scan.mode == ValueScanMode::Snapshot ? "snapshot" : "none";
	return {{"candidates", scan.candidates}, {"results", entries},
		{"scannedBytes", scan.scannedBytes}, {"mode", mode},
		{"valueType", ValueScanTypeName(scan.valueType)}, {"offset", request.offset}};
}

json McpServer::ToolFreeMemory(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	std::string addrStr = args.value("address", "");
	if (addrStr.empty()) return {{"error", "address is required"}};

	uint64_t addr;
	if (!ParseAddress(addrStr, addr)) return {{"error", "invalid address format"}};

	if (!session_.FreeMemory(addr)) {
		return {{"error", "VirtualFree failed"}};
	}
	return {{"success", true}};
}

json McpServer::ToolExecuteShellcode(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	std::string codeHex = args.value("shellcode", "");
	if (codeHex.empty()) return {{"error", "shellcode (hex string) is required"}};
	int timeoutMs = JsonInt(args, "timeout_ms", 5000);
	if (timeoutMs < 0) timeoutMs = 0;
	if (timeoutMs > 60000) timeoutMs = 60000;

	std::vector<uint8_t> bytes;
	std::string clean;
	for (char c : codeHex) {
		if (std::isxdigit(c)) clean += c;
	}
	if (clean.size() % 2 != 0) return {{"error", "Invalid hex string (odd length)"}};
	for (size_t i = 0; i < clean.size(); i += 2) {
		bytes.push_back(static_cast<uint8_t>(std::stoi(clean.substr(i, 2), nullptr, 16)));
	}
	if (bytes.empty()) return {{"error", "Empty shellcode"}};
	if (bytes.size() > 1024 * 1024) return {{"error", "Shellcode too large (max 1MB)"}};

	auto result = session_.ExecuteShellcode(bytes.data(), static_cast<uint32_t>(bytes.size()),
	                                         static_cast<uint32_t>(timeoutMs));
	if (!result.ok) {
		return {{"error", "Shellcode execution failed (alloc or thread creation error)"}};
	}

	char addrBuf[20];
	snprintf(addrBuf, sizeof(addrBuf), "0x%llX", result.allocatedAddress);
	json ret = {
		{"success", true},
		{"exitCode", result.exitCode},
		{"allocatedAddress", addrBuf},
		{"fireAndForget", (timeoutMs == 0)}
	};
	if (result.crashed) {
		char exAddrBuf[20];
		snprintf(exAddrBuf, sizeof(exAddrBuf), "0x%llX", result.exceptionAddress);
		char exCodeBuf[12];
		snprintf(exCodeBuf, sizeof(exCodeBuf), "0x%08X", result.exceptionCode);
		ret["crashed"] = true;
		ret["exceptionCode"] = exCodeBuf;
		ret["exceptionAddress"] = exAddrBuf;
	}
	return ret;
}

json McpServer::ToolAssemble(const json& args) {
	std::string code = args.value("code", "");
	if (code.empty()) return {{"error", "code is required (e.g. \"mov esi, eax; jmp 0x401000\")"}};
	uint64_t address = 0;
	std::string addrStr = args.value("address", "");
	if (!addrStr.empty() && !ParseAddress(addrStr, address)) return {{"error", "invalid address format"}};
	bool write = JsonBool(args, "write", false);
	if (write && (!session_.IsAttached() || addrStr.empty()))
		return {{"error", "write=true needs an attached target and an address"}};

	// Bitness: explicit arch, else the attached target, else x64.
	bool x64 = true;
	std::string arch = args.value("arch", "");
	if (arch == "x86") x64 = false;
	else if (!arch.empty() && arch != "x64") return {{"error", "arch must be x86 or x64"}};
	else if (arch.empty() && session_.IsAttached()) {
		BOOL isWow64 = FALSE;
		if (HANDLE hProc = session_.GetTargetProcess()) IsWow64Process(hProc, &isWow64);
		x64 = !isWow64;
	}

	auto assembled = AssembleText(code, address, x64);
	if (!assembled.ok) {
		json error = {{"error", "assemble failed: " + assembled.error}};
		if (assembled.errorLine) error["line"] = assembled.errorLine;
		return error;
	}

	std::string hex;
	for (uint8_t b : assembled.bytes) {
		char buf[4];
		snprintf(buf, sizeof(buf), hex.empty() ? "%02X" : " %02X", b);
		hex += buf;
	}
	// Decode the result back so the caller sees exactly what was produced.
	json listing = json::array();
	ZydisDisassembler decoder(x64);
	for (auto& insn : decoder.Disassemble(assembled.bytes.data(), static_cast<uint32_t>(assembled.bytes.size()), address, 256))
		listing.push_back({{"address", HexAddr(insn.address)}, {"bytes", insn.bytes}, {"text", insn.mnemonic}});

	json result = {{"address", HexAddr(address)}, {"arch", x64 ? "x64" : "x86"}, {"size", assembled.bytes.size()},
	               {"bytes", hex}, {"listing", listing}};
	if (write) {
		if (!session_.WriteMemory(address, assembled.bytes.data(), static_cast<uint32_t>(assembled.bytes.size())))
			return {{"error", "assembled but the write failed"}, {"bytes", hex}};
		result["written"] = true;
	}
	return result;
}

} // namespace veh
