#include "mcp_server.h"
#include "tools_common.h"
#include <algorithm>
#include <charconv>
#include <limits>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>

// System inspection tools: machine-wide state (physical and kernel memory,
// paging, MSR, CPUID, I/O ports, IDT, APIC, PCI). Only backends running below
// the OS serve them; others answer Unsupported and the tool says so.

namespace veh {

namespace {

constexpr uint32_t kChunk = kSystemMemoryMax;

std::string Hex(const uint8_t* data, size_t size) {
	std::ostringstream oss;
	for (size_t i = 0; i < size; i++) {
		if (i > 0) oss << (i % 16 == 0 ? "\n" : " ");
		oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]);
	}
	return oss.str();
}

std::string Hex32(uint32_t v) {
	char buf[16];
	snprintf(buf, sizeof(buf), "0x%X", v);
	return buf;
}

bool ParseNumber(const json& args, const char* key, uint64_t& out) {
	if (!args.contains(key)) return false;
	const json& v = args[key];
	if (v.is_number_unsigned()) { out = v.get<uint64_t>(); return true; }
	if (v.is_number_integer()) { out = static_cast<uint64_t>(v.get<int64_t>()); return v.get<int64_t>() >= 0; }
	if (!v.is_string()) return false;
	const std::string s = v.get<std::string>();
	char* end = nullptr;
	const bool hex = s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X');
	out = std::strtoull(s.c_str(), &end, hex ? 16 : 10);
	return !s.empty() && end && *end == 0;
}

// Pattern "48 8B ?? 05": bytes with ?? wildcards.
bool ParsePattern(const std::string& text, std::vector<int>& out) {
	std::istringstream in(text);
	std::string token;
	out.clear();
	while (in >> token) {
		if (token == "??" || token == "?") { out.push_back(-1); continue; }
		if (token.size() != 2 || !std::isxdigit(static_cast<unsigned char>(token[0])) ||
			!std::isxdigit(static_cast<unsigned char>(token[1])))
			return false;
		out.push_back(std::stoi(token, nullptr, 16));
	}
	return !out.empty();
}

bool ParseBytes(const std::string& text, std::vector<uint8_t>& out) {
	std::string clean;
	for (char c : text)
		if (std::isxdigit(static_cast<unsigned char>(c))) clean += c;
	if (clean.empty() || clean.size() % 2) return false;
	out.clear();
	for (size_t i = 0; i < clean.size(); i += 2) out.push_back(static_cast<uint8_t>(std::stoi(clean.substr(i, 2), nullptr, 16)));
	return true;
}

const char* StatusText(IpcStatus s) {
	switch (s) {
	case IpcStatus::Ok: return "ok";
	case IpcStatus::NotFound: return "not found";
	case IpcStatus::InvalidArgs: return "invalid arguments or address";
	case IpcStatus::Unsupported: return "unsupported by this backend";
	case IpcStatus::InvalidState: return "operation refused in the current target state";
	default: return "failed";
	}
}

std::string EscapedProcessName(const char* bytes, size_t limit) {
	std::string out;
	for (size_t i = 0; i < limit && bytes[i]; ++i) {
		const auto value = static_cast<unsigned char>(bytes[i]);
		if (value >= 0x20 && value < 0x7f) out.push_back(static_cast<char>(value));
		else {
			char escaped[5]{};
			snprintf(escaped, sizeof(escaped), "\\x%02X", static_cast<unsigned>(value));
			out += escaped;
		}
	}
	return out;
}

} // namespace

// Request/response exchange for one system command, with the backend check.
bool McpServer::SystemExchange(IpcCommand cmd, const void* payload, uint32_t size, std::vector<uint8_t>& response,
	json& error, int timeoutMs) {
	if (!session_.IsAttached()) { error = {{"error", NotAttachedMessage()}}; return false; }
	if (!session_.GetBackendInfo().Supports(cmd)) {
		error = {{"error", "Unavailable: this tool needs a backend running below the OS (attach with a hypervisor "
			"backend). The current backend does not serve system inspection."}};
		return false;
	}
	if (!session_.GetPipeClient().SendAndReceive(cmd, payload, size, response, timeoutMs) ||
		response.size() < sizeof(IpcStatus)) {
		error = {{"error", "no response from the backend"}};
		return false;
	}
	return true;
}


json McpServer::ToolVirtualMachine(const json& args) {
    const std::string op=args.value("operation", "");
    json error;std::vector<uint8_t> bytes;
    if(op=="status"||op=="pause"||op=="resume") {
        const auto action=op=="status"?VirtualMachineAction::Query:
            op=="pause"?VirtualMachineAction::Pause:VirtualMachineAction::Resume;
        ControlVirtualMachineRequest request{action,0};
        if(!SystemExchange(IpcCommand::ControlVirtualMachine,&request,sizeof(request),bytes,error))return error;
        ControlVirtualMachineResponse response{};
        if(bytes.size()!=sizeof(response))return {{"error","Invalid VM control response"}};
        std::memcpy(&response,bytes.data(),sizeof(response));
        if(response.status!=IpcStatus::Ok)return {{"error",StatusText(response.status)},{"scope","virtualMachine"}};
        if(static_cast<uint32_t>(response.state)>3)return {{"error","Invalid VM state"}};
        const char* state=response.state==VirtualMachineState::Running?"running":
            response.state==VirtualMachineState::Paused?"paused":
            response.state==VirtualMachineState::PoweredOff?"poweredOff":"other";
        return {{"success",true},{"scope","virtualMachine"},{"state",state}};
    }
    if(op!="trace")return {{"error","operation must be status, pause, resume or trace"}};
    TraceVirtualCpuRequest request{};
    const auto number=[&](const char* key,uint32_t fallback,uint32_t minimum,uint32_t maximum,uint32_t& out) {
        if(!args.contains(key)){out=fallback;return true;}
        const auto& v=args[key];if(!v.is_number_unsigned()&&!v.is_number_integer())return false;
        if(v.is_number_integer()&&v.get<int64_t>()<0)return false;
        const auto n=v.get<uint64_t>();if(n<minimum||n>maximum)return false;out=static_cast<uint32_t>(n);return true;
    };
    const auto address=[](const json& value,uint64_t& out) {
        if(!value.is_string())return false;const auto s=value.get<std::string>();
        const size_t skip=s.size()>2&&s[0]=='0'&&(s[1]=='x'||s[1]=='X')?2:0;
        const auto parsed=std::from_chars(s.data()+skip,s.data()+s.size(),out,skip?16:10);
        return parsed.ec==std::errc{}&&parsed.ptr==s.data()+s.size();
    };
    if(!number("cpu",0,0,UINT32_MAX,request.cpu)||
       !number("max_instructions",64,1,4096,request.maxInstructions)||
       !number("duration_ms",10,1,100,request.durationMs)||
       !number("cpl_mask",15,1,15,request.cplMask))return {{"error","Invalid CPU, instruction, duration or CPL limit"}};
    for(const auto& field:{std::make_pair("rip_begin",&request.ripBegin),std::make_pair("rip_end",&request.ripEnd)})
        if(args.contains(field.first)&&!address(args[field.first],*field.second))return {{"error","RIP bounds must be exact unsigned address strings"}};
    if(request.ripBegin>request.ripEnd)return {{"error","Reversed RIP bounds"}};
    if(args.contains("cr3_roots")) {
        const auto& roots=args["cr3_roots"];
        if(!roots.is_array()||roots.size()>2)return {{"error","At most two CR3 roots are supported"}};
        for(const auto& root:roots) {
            auto& value=request.cr3Roots[request.cr3Count];
            if(!address(root,value)||!value||(value&~UINT64_C(0x000FFFFFFFFFF000)))return {{"error","CR3 roots must be exact nonzero page-aligned address strings"}};
            ++request.cr3Count;
        }
    }
    if(!SystemExchange(IpcCommand::TraceVirtualCpu,&request,sizeof(request),bytes,error))return error;
    TraceVirtualCpuResponse response{};
    if(bytes.size()<sizeof(response))return {{"error","Invalid vCPU trace response"}};
    std::memcpy(&response,bytes.data(),sizeof(response));
    const uint64_t recorded=static_cast<uint64_t>(response.count)+response.lost;
    if(response.wireVersion!=1||response.engine!=1||response.count>64||response.completed>request.maxInstructions||
       response.lost>response.completed||recorded<response.lost||recorded>response.completed||
       response.stopReason<1||response.stopReason>4||
       bytes.size()!=sizeof(response)+static_cast<size_t>(response.count)*sizeof(VirtualCpuInstructionRecord)||
       (response.status==IpcStatus::Ok&&(recorded!=response.completed||response.executionStatus||response.stopReason==4)))
        return {{"error","Inconsistent vCPU trace accounting"}};
    json records=json::array();
    for(uint32_t i=0;i<response.count;++i) {
        VirtualCpuInstructionRecord record{};
        std::memcpy(&record,bytes.data()+sizeof(response)+static_cast<size_t>(i)*sizeof(record),sizeof(record));
        if(record.cpu!=request.cpu||record.cpl>3||record.sequence!=static_cast<uint64_t>(i)+1)
            return {{"error","Invalid vCPU instruction record"}};
        records.push_back({{"sequence",record.sequence},{"timestampNs",std::to_string(record.timestampNs)},
            {"cpu",record.cpu},{"cpl",record.cpl},{"cr3",HexAddr(record.cr3)},
            {"ip",HexAddr(record.ip)},{"nextIp",HexAddr(record.nextIp)},
            {"rax",HexAddr(record.rax)},{"rbx",HexAddr(record.rbx)},{"rcx",HexAddr(record.rcx)},
            {"rdx",HexAddr(record.rdx)},{"rsp",HexAddr(record.rsp)},{"rflags",HexAddr(record.rflags)}});
    }
    const char* reason=response.stopReason==1?"budget":response.stopReason==2?"deadline":response.stopReason==3?"filter":"failure";
    json result={{"success",response.status==IpcStatus::Ok},{"scope","virtualMachine"},{"traceScope","vCPU"},
        {"cpu",request.cpu},{"engine","interpreter"},{"completed",response.completed},{"kept",response.count},
        {"lost",response.lost},{"elapsedNs",std::to_string(response.elapsedNs)},{"stopReason",reason},
        {"executionStatus",response.executionStatus},{"records",std::move(records)}};
    if(response.status!=IpcStatus::Ok)result["error"]="vCPU execution failed; partial execution and side effects may remain";
    return result;
}

json McpServer::ToolSystemMemory(const json& args) {
	const std::string space = args.value("space", "kernel");
	if (space != "kernel" && space != "physical") return {{"error", "space must be kernel or physical"}};
	const bool physical = space == "physical";
	const std::string op = args.value("operation", "read");
    if(session_.IsVirtualMachineTarget()&&op!="read"&&op!="write")
        return {{"error","VM memory search/dump requires a backend operation; client memory loops are unavailable"}};
	uint64_t address = 0;
	if (!ParseNumber(args, "address", address)) return {{"error", "address is required (hex or decimal)"}};
	json error;
	std::vector<uint8_t> resp;

	const auto read = [&](uint64_t at, uint32_t size, std::vector<uint8_t>& out) -> IpcStatus {
		PhysicalMemoryRequest req{at, size, 0};
		if (!SystemExchange(physical ? IpcCommand::ReadPhysical : IpcCommand::ReadSystemMemory, &req, sizeof(req), resp, error))
			return IpcStatus::Unsupported;
		const IpcStatus status = *reinterpret_cast<const IpcStatus*>(resp.data());
		out.assign(resp.begin() + sizeof(IpcStatus), resp.end());
		return status == IpcStatus::Ok && out.size() == size ? IpcStatus::Ok : (status == IpcStatus::Ok ? IpcStatus::Error : status);
	};

	if (op == "read") {
		const uint64_t size = args.value("size", 64);
		if (size == 0 || size > 1048576) return {{"error", "size must be 1-1048576"}};
		std::vector<uint8_t> all, chunk;
		for (uint64_t done = 0; done < size; done += chunk.size()) {
			const auto n = static_cast<uint32_t>(std::min<uint64_t>(kChunk - ((address + done) & (kChunk - 1)), size - done));
			const IpcStatus status = read(address + done, n, chunk);
			if (!error.is_null()) return error;
			if (status != IpcStatus::Ok) {
				if (all.empty()) return {{"error", std::string("read failed: ") + StatusText(status)}, {"address", HexAddr(address + done)}};
				break;
			}
			all.insert(all.end(), chunk.begin(), chunk.end());
		}
		return {{"space", space}, {"address", HexAddr(address)}, {"size", all.size()}, {"hex", Hex(all.data(), all.size())}};
	}
	if (op == "write") {
		std::vector<uint8_t> bytes;
		if (!ParseBytes(args.value("data", ""), bytes) || bytes.size() > kChunk)
			return {{"error", "data must be hex bytes (at most 65536)"}};
		std::vector<uint8_t> payload(sizeof(PhysicalMemoryRequest) + bytes.size());
		PhysicalMemoryRequest req{address, static_cast<uint32_t>(bytes.size()), 0};
		std::memcpy(payload.data(), &req, sizeof(req));
		std::memcpy(payload.data() + sizeof(req), bytes.data(), bytes.size());
		if (!SystemExchange(physical ? IpcCommand::WritePhysical : IpcCommand::WriteSystemMemory, payload.data(),
				static_cast<uint32_t>(payload.size()), resp, error))
			return error;
		const IpcStatus status = *reinterpret_cast<const IpcStatus*>(resp.data());
		if (status != IpcStatus::Ok) return {{"error", std::string("write failed: ") + StatusText(status)}};
		return {{"success", true}, {"space", space}, {"address", HexAddr(address)}, {"written", bytes.size()}};
	}
	if (op == "search") {
		std::vector<int> pattern;
		if (!ParsePattern(args.value("pattern", ""), pattern)) return {{"error", "pattern must be hex bytes with ?? wildcards, e.g. \"48 8B ?? 05\""}};
		const uint64_t size = args.value("size", 0x100000ull);
		if (size == 0 || size > (1ull << 32)) return {{"error", "size must be 1-4294967296"}};
		const uint32_t max_results = std::clamp<uint32_t>(JsonUint32(args, "max_results", 100), 1, 10000);
		json hits = json::array();
		uint64_t unreadable = 0;
		std::vector<uint8_t> chunk, tail;
		for (uint64_t at = address; at < address + size && hits.size() < max_results;) {
			const auto n = static_cast<uint32_t>(std::min<uint64_t>(kChunk - (at & (kChunk - 1)), address + size - at));
			if (read(at, n, chunk) != IpcStatus::Ok) {
				if (!error.is_null()) return error;
				unreadable += n;
				tail.clear();
				at += n;
				continue;
			}
			std::vector<uint8_t> window(tail);
			const uint64_t window_start = at - tail.size();
			window.insert(window.end(), chunk.begin(), chunk.end());
			for (size_t i = 0; i + pattern.size() <= window.size() && hits.size() < max_results; ++i) {
				bool match = true;
				for (size_t k = 0; k < pattern.size() && match; ++k)
					match = pattern[k] < 0 || window[i + k] == pattern[k];
				if (match) hits.push_back(HexAddr(window_start + i));
			}
			const size_t keep = std::min(window.size(), pattern.size() - 1);
			tail.assign(window.end() - keep, window.end());
			at += n;
		}
		return {{"space", space}, {"matches", hits}, {"count", hits.size()}, {"unreadable_bytes", unreadable},
			{"truncated", hits.size() >= max_results}};
	}
	if (op == "dump") {
		const std::string path = args.value("path", "");
		const uint64_t size = args.value("size", 0ull);
		if (path.empty() || size == 0 || size > (1ull << 34)) return {{"error", "dump needs path and size (at most 16 GiB)"}};
		std::ofstream file(path, std::ios::binary | std::ios::trunc);
		if (!file) return {{"error", "cannot create " + path}};
		uint64_t unreadable = 0;
		std::vector<uint8_t> chunk;
		for (uint64_t at = address; at < address + size;) {
			const auto n = static_cast<uint32_t>(std::min<uint64_t>(kChunk - (at & (kChunk - 1)), address + size - at));
			if (read(at, n, chunk) != IpcStatus::Ok) {
				if (!error.is_null()) return error;
				chunk.assign(n, 0); // unreadable ranges are zero filled
				unreadable += n;
			}
			file.write(reinterpret_cast<const char*>(chunk.data()), n);
			at += n;
		}
		return {{"success", true}, {"path", path}, {"size", size}, {"unreadable_bytes", unreadable}};
	}
	return {{"error", "operation must be read, write, search, or dump"}};
}

json McpServer::ToolTranslate(const json& args) {
	json error;
	std::vector<uint8_t> resp;
	uint64_t value = 0;
	if (ParseNumber(args, "physical", value)) {
		PhysicalToVirtualRequest req{value};
		if (!SystemExchange(IpcCommand::PhysicalToVirtual, &req, sizeof(req), resp, error)) return error;
		if (resp.size() < sizeof(PhysicalToVirtualResponse)) return {{"error", "short response"}};
		const auto* r = reinterpret_cast<const PhysicalToVirtualResponse*>(resp.data());
		if (r->status != IpcStatus::Ok) return {{"error", StatusText(r->status)}};
		return {{"physical", HexAddr(value)}, {"virtual", r->address ? json(HexAddr(r->address)) : json(nullptr)}};
	}
	if (!ParseNumber(args, "address", value)) return {{"error", "address (virtual) or physical is required"}};
	const std::string space = args.value("space", "auto");
	TranslateAddressRequest req{value, 0, 0};
	if (space == "target" || (space == "auto" && value < 0x800000000000ull)) req.flags = kTranslateTargetSpace;
	if (!SystemExchange(IpcCommand::TranslateAddress, &req, sizeof(req), resp, error)) return error;
	if (resp.size() < sizeof(TranslateAddressResponse)) return {{"error", "short response"}};
	const auto* r = reinterpret_cast<const TranslateAddressResponse*>(resp.data());
	if (r->status != IpcStatus::Ok) return {{"error", StatusText(r->status)}};
	static const char* const names5[] = {"pml5e", "pml4e", "pdpte", "pde", "pte"};
	const char* const* names = r->levels == 5 ? names5 : names5 + 1;
	json entries = json::array();
	for (uint32_t i = 0; i < r->entryCount && i < 5; ++i) {
		const uint64_t e = r->entries[i];
		entries.push_back({{"level", names[i]}, {"raw", HexAddr(e)}, {"present", (e & 1) != 0},
			{"writable", (e & 2) != 0}, {"user", (e & 4) != 0}, {"accessed", (e & 0x20) != 0}, {"dirty", (e & 0x40) != 0},
			{"large", (e & 0x80) != 0}, {"no_execute", (e >> 63) != 0}, {"frame", HexAddr(e & 0x000FFFFFFFFFF000ull)}});
	}
	json out = {{"address", HexAddr(value)}, {"space", req.flags ? "target" : "kernel"}, {"cr3", HexAddr(r->cr3)},
		{"levels", r->levels}, {"entries", entries}, {"present", r->present != 0}};
	if (r->present) {
		out["physical"] = HexAddr(r->physical);
		out["page_size"] = r->pageSize;
	}
	return out;
}

json McpServer::ToolMsr(const json& args) {
	uint64_t index = 0, value = 0;
	if (!ParseNumber(args, "index", index) || index > 0xFFFFFFFFull) return {{"error", "index is required (e.g. \"0xC0000082\")"}};
	const bool write = ParseNumber(args, "value", value);
	const bool all = args.value("cpu", json()).is_string() && args["cpu"].get<std::string>() == "all";
	uint64_t cpu = 0;
	if (!all && args.contains("cpu") && !ParseNumber(args, "cpu", cpu)) return {{"error", "cpu must be an index or \"all\""}};
	json results = json::array();
	json error;
	std::vector<uint8_t> resp;
	for (uint32_t c = all ? 0 : static_cast<uint32_t>(cpu); c < (all ? 1024u : static_cast<uint32_t>(cpu) + 1); ++c) {
		AccessMsrRequest req{c, static_cast<uint32_t>(index), write ? 1u : 0u, 0, value};
		if (!SystemExchange(IpcCommand::AccessMsr, &req, sizeof(req), resp, error)) return error;
		if (resp.size() < sizeof(AccessMsrResponse)) return {{"error", "short response"}};
		const auto* r = reinterpret_cast<const AccessMsrResponse*>(resp.data());
		if (r->status == IpcStatus::InvalidArgs && all && c > 0) break; // past the last processor
		if (r->status != IpcStatus::Ok) {
			results.push_back({{"cpu", c}, {"error", r->status == IpcStatus::Error ? "#GP: no such MSR or value refused" : StatusText(r->status)}});
			if (!all) break;
			continue;
		}
		results.push_back({{"cpu", r->cpu}, {"value", HexAddr(r->value)}});
	}
	return {{"index", Hex32(static_cast<uint32_t>(index))}, {"write", write}, {"results", results}};
}

json McpServer::ToolCpuid(const json& args) {
	json error;
	std::vector<uint8_t> resp;
	uint64_t cpu = 0;
	if (args.contains("cpu") && !ParseNumber(args, "cpu", cpu)) return {{"error", "cpu must be an index"}};
	const auto cpuid = [&](uint32_t leaf, uint32_t subleaf, ExecuteCpuidResponse& out) {
		ExecuteCpuidRequest req{static_cast<uint32_t>(cpu), leaf, subleaf, 0};
		if (!SystemExchange(IpcCommand::ExecuteCpuid, &req, sizeof(req), resp, error)) return false;
		if (resp.size() < sizeof(out)) { error = {{"error", "short response"}}; return false; }
		std::memcpy(&out, resp.data(), sizeof(out));
		if (out.status != IpcStatus::Ok) { error = {{"error", StatusText(out.status)}}; return false; }
		return true;
	};
	uint64_t leaf = 0, subleaf = 0;
	ExecuteCpuidResponse r{};
	if (ParseNumber(args, "leaf", leaf)) {
		ParseNumber(args, "subleaf", subleaf);
		if (!cpuid(static_cast<uint32_t>(leaf), static_cast<uint32_t>(subleaf), r)) return error;
		return {{"cpu", r.cpu}, {"leaf", Hex32(static_cast<uint32_t>(leaf))}, {"subleaf", Hex32(static_cast<uint32_t>(subleaf))},
			{"eax", Hex32(r.eax)}, {"ebx", Hex32(r.ebx)}, {"ecx", Hex32(r.ecx)}, {"edx", Hex32(r.edx)}};
	}
	// No leaf: a processor summary (like HyperDbg's `cpu`).
	if (!cpuid(0, 0, r)) return error;
	char vendor[13] = {};
	std::memcpy(vendor, &r.ebx, 4);
	std::memcpy(vendor + 4, &r.edx, 4);
	std::memcpy(vendor + 8, &r.ecx, 4);
	const uint32_t max_leaf = r.eax;
	ExecuteCpuidResponse f1{}, f7{}, x1{};
	cpuid(1, 0, f1);
	if (max_leaf >= 7) cpuid(7, 0, f7);
	char brand[49] = {};
	ExecuteCpuidResponse x{};
	if (cpuid(0x80000000, 0, x) && x.eax >= 0x80000004) {
		for (uint32_t i = 0; i < 3; ++i) {
			ExecuteCpuidResponse b{};
			cpuid(0x80000002 + i, 0, b);
			std::memcpy(brand + i * 16, &b.eax, 16);
		}
		cpuid(0x80000001, 0, x1);
	}
	error = json();
	const uint32_t family = ((f1.eax >> 8) & 0xF) + (((f1.eax >> 8) & 0xF) == 0xF ? (f1.eax >> 20) & 0xFF : 0);
	const uint32_t model = ((f1.eax >> 4) & 0xF) | (((f1.eax >> 16) & 0xF) << 4);
	json features = json::object();
	const auto flag = [&](const char* name, uint32_t reg, int bit) { features[name] = ((reg >> bit) & 1) != 0; };
	flag("vmx", f1.ecx, 5); flag("smx", f1.ecx, 6); flag("hypervisor", f1.ecx, 31); flag("x2apic", f1.ecx, 21);
	flag("aes", f1.ecx, 25); flag("xsave", f1.ecx, 26); flag("avx", f1.ecx, 28); flag("rdrand", f1.ecx, 30);
	flag("pcid", f1.ecx, 17); flag("tsc_deadline", f1.ecx, 24);
	flag("avx2", f7.ebx, 5); flag("smep", f7.ebx, 7); flag("smap", f7.ebx, 20); flag("avx512f", f7.ebx, 16);
	flag("rtm", f7.ebx, 11); flag("intel_pt", f7.ebx, 25); flag("la57", f7.ecx, 16); flag("cet_ss", f7.ecx, 7);
	flag("svm", x1.ecx, 2); flag("nx", x1.edx, 20); flag("rdtscp", x1.edx, 27); flag("page1gb", x1.edx, 26);
	std::string brand_text(brand);
	brand_text.erase(0, brand_text.find_first_not_of(' '));
	return {{"cpu", r.cpu}, {"vendor", vendor}, {"brand", brand_text}, {"family", family}, {"model", model},
		{"stepping", f1.eax & 0xF}, {"max_leaf", Hex32(max_leaf)}, {"features", features}};
}

json McpServer::ToolPortIo(const json& args) {
	uint64_t port = 0, value = 0;
	if (!ParseNumber(args, "port", port) || port > 0xFFFF) return {{"error", "port is required (0-0xFFFF)"}};
	const uint32_t size = JsonUint32(args, "size", 1);
	if (size != 1 && size != 2 && size != 4) return {{"error", "size must be 1, 2 or 4"}};
	const bool write = ParseNumber(args, "value", value);
	AccessPortRequest req{static_cast<uint16_t>(port), static_cast<uint8_t>(size), static_cast<uint8_t>(write), static_cast<uint32_t>(value)};
	json error;
	std::vector<uint8_t> resp;
	if (!SystemExchange(IpcCommand::AccessPort, &req, sizeof(req), resp, error)) return error;
	if (resp.size() < sizeof(AccessPortResponse)) return {{"error", "short response"}};
	const auto* r = reinterpret_cast<const AccessPortResponse*>(resp.data());
	if (r->status != IpcStatus::Ok) return {{"error", StatusText(r->status)}};
	return {{"port", Hex32(static_cast<uint32_t>(port))}, {"size", size}, {"write", write}, {"value", Hex32(r->value)}};
}

// Kernel module + offset for an address (IDT handlers, interrupt routines).
json McpServer::KernelLocation(uint64_t address, const std::vector<SystemModuleEntry>& modules) {
	for (const auto& m : modules) {
		if (address >= m.base && address < m.base + m.size) {
			std::string name = m.path;
			const size_t slash = name.find_last_of("\\/");
			if (slash != std::string::npos) name = name.substr(slash + 1);
			char buf[32];
			snprintf(buf, sizeof(buf), "+0x%llX", static_cast<unsigned long long>(address - m.base));
			return name + buf;
		}
	}
	return nullptr;
}

std::vector<SystemModuleEntry> McpServer::SystemModules(json& error) {
	std::vector<uint8_t> resp;
	std::vector<SystemModuleEntry> out;
	if (!SystemExchange(IpcCommand::GetSystemModules, nullptr, 0, resp, error)) return out;
	if (resp.size() < sizeof(GetSystemModulesResponse)) return out;
	const auto* head = reinterpret_cast<const GetSystemModulesResponse*>(resp.data());
	const size_t count = std::min<size_t>(head->count, (resp.size() - sizeof(*head)) / sizeof(SystemModuleEntry));
	const auto* entries = reinterpret_cast<const SystemModuleEntry*>(resp.data() + sizeof(*head));
	out.assign(entries, entries + count);
	return out;
}

json McpServer::ToolProcesses(const json& args) {
	if (!args.is_object() || !args.empty()) return {{"error", "veh_processes takes no arguments"}};
	json error;
	std::vector<uint8_t> bytes;
	if (!SystemExchange(IpcCommand::GetProcesses, nullptr, 0, bytes, error)) return error;
	if (bytes.size() == sizeof(IpcStatus)) {
		IpcStatus status{};
		std::memcpy(&status, bytes.data(), sizeof(status));
		return {{"error", status == IpcStatus::Ok ? "short process response" : StatusText(status)}};
	}
	if (bytes.size() < sizeof(GetProcessesResponse)) return {{"error", "short process response"}};
	GetProcessesResponse head{};
	std::memcpy(&head, bytes.data(), sizeof(head));
	if (head.status != IpcStatus::Ok) return {{"error", StatusText(head.status)}};
	constexpr uint32_t kMaxProcesses = 4096;
	if (head.count > kMaxProcesses ||
		bytes.size() != sizeof(head) + static_cast<size_t>(head.count) * sizeof(GuestProcessInfo))
		return {{"error", "invalid process response length"}};
	json list = json::array();
	for (uint32_t i = 0; i < head.count; ++i) {
		GuestProcessInfo entry{};
		std::memcpy(&entry, bytes.data() + sizeof(head) + static_cast<size_t>(i) * sizeof(entry), sizeof(entry));
		if (entry.addressBits != 32 && entry.addressBits != 64)
			return {{"error", "invalid process address width"}};
		list.push_back({{"pid", entry.pid}, {"addressBits", entry.addressBits},
			{"name", EscapedProcessName(entry.name, sizeof(entry.name))}});
	}
	return {{"count", list.size()}, {"processes", std::move(list)}};
}

json McpServer::ToolKernelModules(const json& args) {
	json error;
	const auto modules = SystemModules(error);
	if (!error.is_null()) return error;
	std::string filter = args.value("filter", "");
	std::transform(filter.begin(), filter.end(), filter.begin(), ::tolower);
	json list = json::array();
	for (const auto& m : modules) {
		std::string path = m.path;
		std::string lower = path;
		std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
		if (!filter.empty() && lower.find(filter) == std::string::npos) continue;
		list.push_back({{"base", HexAddr(m.base)}, {"size", Hex32(m.size)}, {"path", path}});
	}
	return {{"count", list.size()}, {"total", modules.size()}, {"modules", list}};
}

json McpServer::ToolIdt(const json& args) {
	uint64_t cpu = 0;
	if (args.contains("cpu") && !ParseNumber(args, "cpu", cpu)) return {{"error", "cpu must be an index"}};
	QueryIdtRequest req{static_cast<uint32_t>(cpu)};
	json error;
	std::vector<uint8_t> resp;
	if (!SystemExchange(IpcCommand::QueryIdt, &req, sizeof(req), resp, error)) return error;
	if (resp.size() < sizeof(QueryIdtResponse)) return {{"error", "short response"}};
	const auto* head = reinterpret_cast<const QueryIdtResponse*>(resp.data());
	if (head->status != IpcStatus::Ok) return {{"error", StatusText(head->status)}};
	const auto modules = SystemModules(error);
	const size_t count = std::min<size_t>(head->count, (resp.size() - sizeof(*head)) / sizeof(IdtEntry));
	const auto* entries = reinterpret_cast<const IdtEntry*>(resp.data() + sizeof(*head));
	json list = json::array();
	for (size_t v = 0; v < count; ++v) {
		const IdtEntry& e = entries[v];
		if (!e.present && !JsonBool(args, "include_absent", false)) continue;
		list.push_back({{"vector", Hex32(static_cast<uint32_t>(v))}, {"handler", HexAddr(e.handler)},
			{"location", KernelLocation(e.handler, modules)}, {"selector", Hex32(e.selector)}, {"ist", e.ist},
			{"type", e.type == 14 ? "interrupt" : e.type == 15 ? "trap" : "other"}, {"dpl", e.dpl}});
	}
	return {{"cpu", head->cpu}, {"base", HexAddr(head->base)}, {"limit", Hex32(head->limit)}, {"entries", list}};
}

json McpServer::ToolApic(const json& args) {
	json error;
	std::vector<uint8_t> resp;
	if (args.value("kind", "local") == "io") {
		if (!SystemExchange(IpcCommand::QueryIoApic, nullptr, 0, resp, error)) return error;
		if (resp.size() < sizeof(QueryIoApicResponse)) return {{"error", "short response"}};
		const auto* head = reinterpret_cast<const QueryIoApicResponse*>(resp.data());
		if (head->status != IpcStatus::Ok) return {{"error", StatusText(head->status)}};
		const size_t count = std::min<size_t>(head->count, (resp.size() - sizeof(*head)) / sizeof(IoApicRedirection));
		const auto* entries = reinterpret_cast<const IoApicRedirection*>(resp.data() + sizeof(*head));
		static const char* const modes[] = {"fixed", "lowest", "smi", "reserved", "nmi", "init", "reserved", "extint"};
		json list = json::array();
		for (size_t i = 0; i < count; ++i) {
			const uint64_t e = entries[i].entry;
			list.push_back({{"input", i}, {"gsi", head->gsiBase + i}, {"raw", HexAddr(e)}, {"vector", Hex32(e & 0xFF)},
				{"delivery", modes[(e >> 8) & 7]}, {"logical", ((e >> 11) & 1) != 0}, {"active_low", ((e >> 13) & 1) != 0},
				{"level", ((e >> 15) & 1) != 0}, {"masked", ((e >> 16) & 1) != 0}, {"destination", Hex32(static_cast<uint32_t>(e >> 56))}});
		}
		return {{"id", head->id}, {"address", HexAddr(head->address)}, {"gsi_base", head->gsiBase},
			{"version", Hex32(head->version & 0xFF)}, {"entries", list}};
	}
	uint64_t cpu = 0;
	if (args.contains("cpu") && !ParseNumber(args, "cpu", cpu)) return {{"error", "cpu must be an index"}};
	QueryApicRequest req{static_cast<uint32_t>(cpu)};
	if (!SystemExchange(IpcCommand::QueryApic, &req, sizeof(req), resp, error)) return error;
	if (resp.size() < sizeof(QueryApicResponse)) return {{"error", "short response"}};
	const auto* head = reinterpret_cast<const QueryApicResponse*>(resp.data());
	if (head->status != IpcStatus::Ok) return {{"error", StatusText(head->status)}};
	const size_t count = std::min<size_t>(head->count, (resp.size() - sizeof(*head)) / sizeof(ApicRegister));
	const auto* regs = reinterpret_cast<const ApicRegister*>(resp.data() + sizeof(*head));
	const auto name = [](uint32_t offset) -> std::string {
		switch (offset) {
		case 0x020: return "id"; case 0x030: return "version"; case 0x080: return "tpr"; case 0x0A0: return "ppr";
		case 0x0D0: return "ldr"; case 0x0E0: return "dfr"; case 0x0F0: return "svr"; case 0x280: return "esr";
		case 0x2F0: return "lvt_cmci"; case 0x300: return "icr_low"; case 0x310: return "icr_high";
		case 0x320: return "lvt_timer"; case 0x330: return "lvt_thermal"; case 0x340: return "lvt_perf";
		case 0x350: return "lvt_lint0"; case 0x360: return "lvt_lint1"; case 0x370: return "lvt_error";
		case 0x380: return "timer_initial"; case 0x390: return "timer_current"; case 0x3E0: return "timer_divide";
		}
		if (offset >= 0x100 && offset < 0x180) return "isr" + std::to_string((offset - 0x100) / 16);
		if (offset >= 0x180 && offset < 0x200) return "tmr" + std::to_string((offset - 0x180) / 16);
		if (offset >= 0x200 && offset < 0x280) return "irr" + std::to_string((offset - 0x200) / 16);
		return Hex32(offset);
	};
	json registers = json::object();
	for (size_t i = 0; i < count; ++i) registers[name(regs[i].offset)] = Hex32(regs[i].value);
	return {{"cpu", head->cpu}, {"base_msr", HexAddr(head->baseMsr)}, {"mode", head->x2apic ? "x2apic" : "xapic"},
		{"enabled", ((head->baseMsr >> 11) & 1) != 0}, {"registers", registers}};
}

json McpServer::ToolPci(const json& args) {
	json error;
	std::vector<uint8_t> resp;
	const auto config = [&](uint8_t bus, uint8_t dev, uint8_t fn, uint16_t offset, uint16_t size, std::vector<uint8_t>& out) {
		AccessPciConfigRequest req{bus, dev, fn, 0, offset, size};
		if (!SystemExchange(IpcCommand::AccessPciConfig, &req, sizeof(req), resp, error)) return IpcStatus::Unsupported;
		out.assign(resp.begin() + sizeof(IpcStatus), resp.end());
		return *reinterpret_cast<const IpcStatus*>(resp.data());
	};
	const std::string op = args.value("operation", "tree");
	if (op == "tree") {
		// Bus 0 plus every bus a bridge leads to.
		json devices = json::array();
		std::vector<uint8_t> buses = {0}, seen(256, 0), cfg;
		seen[0] = 1;
		for (size_t b = 0; b < buses.size(); ++b) {
			for (uint8_t dev = 0; dev < 32; ++dev) {
				for (uint8_t fn = 0; fn < 8; ++fn) {
					const IpcStatus status = config(buses[b], dev, fn, 0, 0x40, cfg);
					if (!error.is_null()) return error;
					if (status != IpcStatus::Ok || cfg.size() < 0x40) {
						if (fn == 0) break;
						continue;
					}
					const uint16_t vendor = cfg[0] | cfg[1] << 8, device = cfg[2] | cfg[3] << 8;
					const uint8_t header = cfg[0x0E];
					json d = {{"bus", buses[b]}, {"device", dev}, {"function", fn}, {"vendor_id", Hex32(vendor)},
						{"device_id", Hex32(device)}, {"class", Hex32(cfg[0x0B])}, {"subclass", Hex32(cfg[0x0A])},
						{"prog_if", Hex32(cfg[0x09])}, {"revision", cfg[0x08]}, {"header_type", header & 0x7F}};
					if ((header & 0x7F) == 1) { // PCI-to-PCI bridge: follow its secondary bus
						d["secondary_bus"] = cfg[0x19];
						if (!seen[cfg[0x19]]) { seen[cfg[0x19]] = 1; buses.push_back(cfg[0x19]); }
					}
					devices.push_back(d);
					if (fn == 0 && !(header & 0x80)) break; // single-function device
				}
			}
		}
		return {{"count", devices.size()}, {"devices", devices}};
	}
	const uint32_t bus = JsonUint32(args, "bus", 0), dev = JsonUint32(args, "device", 0), fn = JsonUint32(args, "function", 0);
	if (bus > 255 || dev > 31 || fn > 7) return {{"error", "bus 0-255, device 0-31, function 0-7"}};
	const uint32_t offset = JsonUint32(args, "offset", 0);
	if (op == "read") {
		const uint32_t size = JsonUint32(args, "size", 256 - offset);
		if (!size || offset + size > 256) return {{"error", "offset + size must be within 256"}};
		std::vector<uint8_t> cfg;
		const IpcStatus status = config(static_cast<uint8_t>(bus), static_cast<uint8_t>(dev), static_cast<uint8_t>(fn),
			static_cast<uint16_t>(offset), static_cast<uint16_t>(size), cfg);
		if (!error.is_null()) return error;
		if (status != IpcStatus::Ok) return {{"error", status == IpcStatus::NotFound ? "no device at that address" : StatusText(status)}};
		return {{"bus", bus}, {"device", dev}, {"function", fn}, {"offset", Hex32(offset)}, {"hex", Hex(cfg.data(), cfg.size())}};
	}
	if (op == "write") {
		std::vector<uint8_t> bytes;
		if (!ParseBytes(args.value("data", ""), bytes) || offset + bytes.size() > 256) return {{"error", "data must be hex bytes within the 256-byte space"}};
		std::vector<uint8_t> payload(sizeof(AccessPciConfigRequest) + bytes.size());
		AccessPciConfigRequest req{static_cast<uint8_t>(bus), static_cast<uint8_t>(dev), static_cast<uint8_t>(fn), 1,
			static_cast<uint16_t>(offset), static_cast<uint16_t>(bytes.size())};
		std::memcpy(payload.data(), &req, sizeof(req));
		std::memcpy(payload.data() + sizeof(req), bytes.data(), bytes.size());
		if (!SystemExchange(IpcCommand::AccessPciConfig, payload.data(), static_cast<uint32_t>(payload.size()), resp, error)) return error;
		const IpcStatus status = *reinterpret_cast<const IpcStatus*>(resp.data());
		if (status != IpcStatus::Ok) return {{"error", StatusText(status)}};
		return {{"success", true}, {"written", bytes.size()}};
	}
	return {{"error", "operation must be tree, read, or write"}};
}

json McpServer::ToolTransparency(const json& args) {
	const std::string timing = args.value("timing", "");
	if (!timing.empty() && timing != "on" && timing != "off") return {{"error", "timing must be on or off"}};
	ConfigureTransparencyRequest req{timing == "on" ? 1u : timing == "off" ? 0u : 2u, JsonBool(args, "measure", false) ? 1u : 0u};
	json error;
	std::vector<uint8_t> resp;
	if (!SystemExchange(IpcCommand::ConfigureTransparency, &req, sizeof(req), resp, error)) return error;
	if (resp.size() < sizeof(ConfigureTransparencyResponse)) return {{"error", "short response"}};
	const auto* r = reinterpret_cast<const ConfigureTransparencyResponse*>(resp.data());
	if (r->status != IpcStatus::Ok) return {{"error", StatusText(r->status)}};
	json out = {{"timing", r->timing ? "on" : "off"}, {"exit_cost_cycles", r->exitCost}};
	if (req.measure) out["cpuid_cycles"] = {{"seen_without", r->cpuidCycles}, {"seen_with", r->cpuidCyclesHidden}};
	return out;
}

json McpServer::ToolAddressSpace(const json& args) {
	static const char* const names[] = {"auto", "kernel_record", "user_shadow", "observed", "probe", "scan", "all"};
	const std::string method = args.value("method", "auto");
	uint32_t m = 0;
	while (m < 7 && method != names[m]) ++m;
	if (m == 7) return {{"error", "method must be auto, kernel_record, user_shadow, observed, probe, scan, or all"}};
	const std::string use = args.value("use", "");
	if (!use.empty() && use != "chosen" && use != "os") return {{"error", "use must be chosen or os"}};
	ResolveAddressSpaceRequest req{static_cast<AddressSpaceMethod>(m), use == "chosen" ? 1u : use == "os" ? 2u : 0u,
		JsonUint32(args, "probe_ms", 100), 0};
	json error;
	std::vector<uint8_t> resp;
	// End-to-end budget: the backend may scan for 60s, plus target-page
	// fault-ins, root validation and application. A frontend wait timeout is
	// not cancellation of those effects.
	constexpr int kResolveBudgetMs = 180000;
	if (!SystemExchange(IpcCommand::ResolveAddressSpace, &req, sizeof(req), resp, error, kResolveBudgetMs)) return error;
	if (resp.size() < sizeof(ResolveAddressSpaceResponse)) return {{"error", "short response"}};
	const auto* head = reinterpret_cast<const ResolveAddressSpaceResponse*>(resp.data());
	if (head->status != IpcStatus::Ok) return {{"error", StatusText(head->status)}};
	const size_t count = std::min<size_t>(head->count, (resp.size() - sizeof(*head)) / sizeof(AddressSpaceCandidate));
	const auto* list = reinterpret_cast<const AddressSpaceCandidate*>(resp.data() + sizeof(*head));
	json candidates = json::array();
	for (size_t i = 0; i < count; ++i) {
		const uint32_t cm = static_cast<uint32_t>(list[i].method);
		candidates.push_back({{"method", cm < 7 ? names[cm] : "?"}, {"root", HexAddr(list[i].root)}, {"valid", list[i].valid != 0}});
	}
	json out = {{"candidates", candidates}, {"in_use", HexAddr(head->inUse)}};
	if (head->chosen < count) out["chosen"] = HexAddr(list[head->chosen].root);
	if (m == 4 || m == 6 || head->probed) out["probe_roots_seen"] = head->probed;
	return out;
}

namespace {

const char* const kEventNames[] = { "", "cpuid", "msr_read", "msr_write", "exception", "port_in", "port_out", "syscall",
	"hypercall", "xsetbv", "rdtsc", "memory_read", "memory_write", "memory_execute", "dr_access", "sysret",
	"interrupt" };

uint32_t EventTypeOf(const std::string& name) {
	for (uint32_t i = 1; i < sizeof(kEventNames) / sizeof(kEventNames[0]); ++i)
		if (name == kEventNames[i]) return i;
	return 0;
}

std::string EventName(uint32_t type) {
	return type < sizeof(kEventNames) / sizeof(kEventNames[0]) ? kEventNames[type] : std::to_string(type);
}

json PrivilegeJson(uint32_t privilege) {
	return privilege == 1 ? "kernel" : privilege == 2 ? "user" : "any";
}

} // namespace

json McpServer::ToolEvent(const json& args) {
	const std::string op = args.value("operation", "list");
	json error;
	std::vector<uint8_t> resp;
	if (op == "add") {
		AddSystemEventRequest req{};
		req.type = EventTypeOf(args.value("type", ""));
		if (!req.type) return {{"error", "type: cpuid, msr_read, msr_write, exception, port_in, port_out, syscall, sysret, hypercall, xsetbv, rdtsc, dr_access, interrupt, memory_read, memory_write, memory_execute"}};
		req.action = args.value("action", "record") == "stop" ? 1u : 0u;
		req.pid = JsonUint32(args, "pid", 0);
		req.tid = JsonUint32(args, "tid", 0);
		req.cpu = args.contains("cpu") ? JsonUint32(args, "cpu", 0) : ~0u;
		const std::string mode = args.value("mode", "any");
		req.privilege = mode == "kernel" ? 1u : mode == "user" ? 2u : 0u;
		uint64_t low = 0, high = ~0ull;
		if (ParseNumber(args, "value", low)) high = low;
		ParseNumber(args, "low", low);
		ParseNumber(args, "high", high);
		uint64_t size = 0;
		if (ParseNumber(args, "address", low)) {
			high = low + (ParseNumber(args, "size", size) && size ? size - 1 : 0);
		}
		req.low = low;
		req.high = high;
		if (!SystemExchange(IpcCommand::AddSystemEvent, &req, sizeof(req), resp, error)) return error;
		if (resp.size() < sizeof(AddSystemEventResponse)) return {{"error", "short response"}};
		const auto* r = reinterpret_cast<const AddSystemEventResponse*>(resp.data());
		if (r->status != IpcStatus::Ok) return {{"error", std::string("not added: ") + StatusText(r->status)}};
		return {{"id", r->id}, {"type", EventName(req.type)}, {"action", req.action ? "stop" : "record"},
			{"note", "records: veh_event_records"}};
	}
	if (op == "remove") {
		RemoveSystemEventRequest req{args.contains("id") ? JsonUint32(args, "id", 0) : ~0u};
		if (!SystemExchange(IpcCommand::RemoveSystemEvent, &req, sizeof(req), resp, error)) return error;
		const IpcStatus status = *reinterpret_cast<const IpcStatus*>(resp.data());
		if (status != IpcStatus::Ok) return {{"error", StatusText(status)}};
		return {{"removed", args.contains("id") ? json(req.id) : json("all")}};
	}
	if (op != "list") return {{"error", "operation: add, remove, list"}};
	if (!SystemExchange(IpcCommand::ListSystemEvents, nullptr, 0, resp, error)) return error;
	if (resp.size() < sizeof(ListSystemEventsResponse)) return {{"error", "short response"}};
	const auto* head = reinterpret_cast<const ListSystemEventsResponse*>(resp.data());
	json list = json::array();
	const auto* e = reinterpret_cast<const SystemEventInfo*>(head + 1);
	for (uint32_t i = 0; i < head->count && sizeof(*head) + (i + 1) * sizeof(*e) <= resp.size(); ++i)
		list.push_back({{"id", e[i].id}, {"type", EventName(e[i].type)},
			{"action", e[i].action == 2 ? "edit" : e[i].action ? "stop" : "record"},
			{"pid", e[i].pid}, {"tid", e[i].tid}, {"cpu", e[i].cpu == ~0u ? json("any") : json(e[i].cpu)},
			{"mode", PrivilegeJson(e[i].privilege)}, {"low", HexAddr(e[i].low)}, {"high", HexAddr(e[i].high)},
			{"hits", e[i].hits}});
	return {{"events", list}};
}

json McpServer::ToolHiddenHook(const json& args) {
	static const char* const kRegs[] = { "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10",
		"r11", "r12", "r13", "r14", "r15", "rip", "rflags" };
	const std::string op = args.value("operation", "list");
	if (op == "remove")
		return ToolEvent({{"operation", "remove"}, {"id", JsonUint32(args, "id", 0)}});
	if (op == "list") {
		json all = ToolEvent({{"operation", "list"}});
		if (!all.contains("events")) return all;
		json hooks = json::array();
		for (auto& e : all["events"])
			if (e.value("type", "") == "memory_execute" && e.value("action", "") != "record" && e.value("action", "") != "stop")
				hooks.push_back(e);
		return {{"hooks", hooks}};
	}
	if (op != "add") return {{"error", "operation: add, remove, list"}};
	AddHiddenHookRequest req{};
	if (!ParseNumber(args, "address", req.address)) return {{"error", "address is required"}};
	req.pid = JsonUint32(args, "pid", 0);
	if (args.contains("set")) {
		for (auto& [name, value] : args["set"].items()) {
			int n = -1;
			for (int i = 0; i < 18; ++i)
				if (name == kRegs[i]) n = i;
			uint64_t v = 0;
			const json one = {{"v", value}};
			if (n < 0 || !ParseNumber(one, "v", v)) return {{"error", "set: unknown register or value: " + name}};
			req.regMask |= 1u << n;
			req.values[n] = v;
		}
	}
	if (args.contains("return")) {
		req.returnNow = 1;
		if (!ParseNumber(args, "return", req.returnValue)) return {{"error", "return: a value"}};
		req.returnPop = JsonUint32(args, "pop", 0);
	}
	if (!req.regMask && !req.returnNow) return {{"error", "nothing to do: give set and/or return"}};
	json error;
	std::vector<uint8_t> resp;
	if (!SystemExchange(IpcCommand::AddHiddenHook, &req, sizeof(req), resp, error)) return error;
	if (resp.size() < sizeof(AddHiddenHookResponse)) return {{"error", "short response"}};
	const auto* r = reinterpret_cast<const AddHiddenHookResponse*>(resp.data());
	if (r->status != IpcStatus::Ok) return {{"error", std::string("not added: ") + StatusText(r->status)}};
	return {{"id", r->id}, {"address", HexAddr(req.address)}, {"pid", req.pid},
		{"note", "every hit is also a veh_event_records entry (type memory_execute)"}};
}

json McpServer::ToolBranchTrace(const json& args) {
	const std::string op = args.value("operation", "status");
	const std::string kind_name = args.value("kind", "last");
	const uint32_t kind = kind_name == "full" ? 2u : 1u;
	json error;
	std::vector<uint8_t> resp;
	if (op == "status") {
		if (!SystemExchange(IpcCommand::QueryBranchTrace, nullptr, 0, resp, error)) return error;
		if (resp.size() < sizeof(QueryBranchTraceResponse)) return {{"error", "short response"}};
		const auto* q = reinterpret_cast<const QueryBranchTraceResponse*>(resp.data());
		json out = {{"provider", q->provider}, {"active", q->active == 2 ? "full" : q->active == 1 ? "last" : "none"},
			{"last_branches", {{"available", q->lastBranches != 0}, {"depth", q->lastBranchDepth}}},
			{"full_path", {{"available", q->fullPath != 0}}}};
		if (!q->lastBranches) out["last_branches"]["reason"] = q->lastBranchesReason;
		if (!q->fullPath) out["full_path"]["reason"] = q->fullPathReason;
		if (!q->lastBranches && !q->fullPath)
			out["alternative"] = "veh_trace_basic_blocks traces by single-stepping: slower, works everywhere";
		return out;
	}
	if (op == "start" || op == "stop") {
		StartBranchTraceRequest req{kind, JsonUint32(args, "buffer_kb", 0)};
		if (!SystemExchange(op == "start" ? IpcCommand::StartBranchTrace : IpcCommand::StopBranchTrace, &req,
				sizeof(req), resp, error))
			return error;
		const IpcStatus status = *reinterpret_cast<const IpcStatus*>(resp.data());
		if (status != IpcStatus::Ok) {
			json out = {{"error", std::string(op) + " failed: " + StatusText(status)}};
			if (op == "start") out["hint"] = "veh_branch_trace status says why";
			return out;
		}
		return {{op == "start" ? "started" : "stopped", kind_name}};
	}
	if (op != "read") return {{"error", "operation: status, start, stop, read"}};
	ReadBranchTraceRequest req{kind, JsonUint32(args, "threadId", 0), JsonUint32(args, "max", 4096)};
	if (!SystemExchange(IpcCommand::ReadBranchTrace, &req, sizeof(req), resp, error)) return error;
	if (resp.size() < sizeof(ReadBranchTraceResponse)) return {{"error", "short response"}};
	const auto* head = reinterpret_cast<const ReadBranchTraceResponse*>(resp.data());
	if (head->status != IpcStatus::Ok) return {{"error", std::string("read failed: ") + StatusText(head->status)}};
	const auto* b = reinterpret_cast<const BranchRecord*>(head + 1);
	json list = json::array();
	for (uint32_t i = 0; i < head->count && sizeof(*head) + (i + 1) * sizeof(*b) <= resp.size(); ++i)
		list.push_back({{"from", HexAddr(b[i].from)}, {"to", HexAddr(b[i].to)}});
	return {{"kind", kind_name}, {"branches", list}, {"count", head->count}, {"lost", head->lost}};
}

json McpServer::ToolEventRecords(const json& args) {
	DrainSystemEventsRequest req{JsonUint32(args, "max", 256)};
	json error;
	std::vector<uint8_t> resp;
	if (!SystemExchange(IpcCommand::DrainSystemEvents, &req, sizeof(req), resp, error)) return error;
	if (resp.size() < sizeof(DrainSystemEventsResponse)) return {{"error", "short response"}};
	const auto* head = reinterpret_cast<const DrainSystemEventsResponse*>(resp.data());
	if (head->status != IpcStatus::Ok) return {{"error", StatusText(head->status)}};
	const auto* r = reinterpret_cast<const SystemEventRecord*>(head + 1);
	json list = json::array();
	for (uint32_t i = 0; i < head->count && sizeof(*head) + (i + 1) * sizeof(*r) <= resp.size(); ++i) {
		json j = {{"id", r[i].id}, {"type", EventName(r[i].type)}, {"cpu", r[i].cpu}, {"pid", r[i].pid},
			{"tid", r[i].tid}, {"mode", r[i].privilege == 3 ? "user" : "kernel"}, {"value", HexAddr(r[i].value)},
			{"detail", HexAddr(r[i].detail)}, {"rip", HexAddr(r[i].rip)}, {"rsp", HexAddr(r[i].rsp)},
			{"cr3", HexAddr(r[i].pageTable)}, {"timestamp", r[i].timestamp}};
		if (JsonBool(args, "registers", false))
			j["registers"] = {{"rax", HexAddr(r[i].rax)}, {"rbx", HexAddr(r[i].rbx)}, {"rcx", HexAddr(r[i].rcx)},
				{"rdx", HexAddr(r[i].rdx)}, {"r8", HexAddr(r[i].r8)}, {"r9", HexAddr(r[i].r9)},
				{"r10", HexAddr(r[i].r10)}, {"r11", HexAddr(r[i].r11)}};
		list.push_back(j);
	}
	return {{"records", list}, {"count", head->count}, {"dropped", head->dropped}};
}

} // namespace veh
