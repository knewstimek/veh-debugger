// Halting kernel debugging over the GDB remote serial protocol. Independent of
// the attached process: the debugger stops every CPU of the target machine.
#include "mcp_server.h"
#include "tools_common.h"
#include "kernel_debug_client.h"
#include "../adapter/disassembler.h"
#include <cstring>

namespace veh {
namespace {

const char* const kGdbRegs[] = { "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11",
	"r12", "r13", "r14", "r15", "rip" };
const char* const kGdbSegs[] = { "cs", "ss", "ds", "es", "fs", "gs" };

uint64_t ParseHex(const std::string& s)
{
	return std::strtoull(s.c_str(), nullptr, 16);
}

std::string HexBytes(const std::vector<uint8_t>& b)
{
	static const char h[] = "0123456789abcdef";
	std::string out;
	for (uint8_t v : b) {
		out += h[v >> 4];
		out += h[v & 15];
	}
	return out;
}

std::vector<uint8_t> FromHex(const std::string& s)
{
	std::vector<uint8_t> out;
	std::string digits;
	for (char c : s)
		if (std::isxdigit(static_cast<unsigned char>(c)))
			digits += c;
	for (size_t i = 0; i + 1 < digits.size(); i += 2)
		out.push_back(static_cast<uint8_t>(std::stoul(digits.substr(i, 2), nullptr, 16)));
	return out;
}

uint64_t Le(const std::vector<uint8_t>& b, size_t at, size_t size)
{
	uint64_t v = 0;
	for (size_t i = 0; i < size && at + i < b.size(); ++i)
		v |= static_cast<uint64_t>(b[at + i]) << (8 * i);
	return v;
}

// "T05thread:2;swbreak:;" -> {signal, cpu}
json StopJson(const std::string& stop)
{
	json j = {{"raw", stop}};
	if (stop.size() >= 3 && (stop[0] == 'T' || stop[0] == 'S')) {
		const int sig = std::stoi(stop.substr(1, 2), nullptr, 16);
		j["reason"] = sig == 5 ? "breakpoint or step" : sig == 2 ? "interrupt" : "signal " + std::to_string(sig);
		for (const char* tag : { "awatch:", "rwatch:", "watch:" }) {
			const size_t w = stop.find(tag);
			if (w != std::string::npos && (w == 0 || stop[w - 1] == ';' || stop[w - 1] == ':' || std::isxdigit(static_cast<unsigned char>(stop[w - 1])))) {
				j["reason"] = "watchpoint";
				j["data_address"] = "0x" + stop.substr(w + std::strlen(tag), stop.find(';', w) - w - std::strlen(tag));
				break;
			}
		}
		const size_t t = stop.find("thread:");
		if (t != std::string::npos)
			j["cpu"] = std::stoi(stop.substr(t + 7), nullptr, 16) - 1;
	}
	return j;
}

std::string MonitorText(KernelDebugClient& kd, const std::string& command)
{
	std::string reply;
	std::vector<uint8_t> text(command.begin(), command.end());
	if (!kd.Monitor(HexBytes(text), &reply) || reply.empty())
		return "";
	const auto bytes = FromHex(reply);
	return std::string(bytes.begin(), bytes.end());
}

} // namespace

json McpServer::KdNotConnected() const
{
	return {{"error", "not connected: veh_kd_connect first"}};
}

bool McpServer::KdSelect(const json& args, json& error)
{
	if (!args.contains("cpu"))
		return true;
	std::string reply;
	const int cpu = JsonInt(args, "cpu", 0);
	char selection[32];
	std::snprintf(selection, sizeof(selection), "Hg%x", cpu + 1);
	if (cpu < 0 || cpu >= 64 || !kd_->Request(selection, &reply) || reply != "OK") {
		error = {{"error", "no such cpu"}, {"cpu", cpu}};
		return false;
	}
	return true;
}

json McpServer::ToolKdConnect(const json& args)
{
	const std::string transport = args.value("transport", "pipe");
	const std::string address = args.value("address", "");
	if (address.empty())
		return {{"error", "address required (pipe name, COM port, host:port or ip:port)"}};
	if (kd_)
		(void)ToolKdDisconnect(json::object()); // its breakpoints out, then D
	kd_.reset();
	std::string error;
	auto link = OpenKdTransport(transport, address, JsonUint32(args, "baud", 115200), &error);
	if (!link)
		return {{"error", error}};
	auto client = std::make_unique<KernelDebugClient>(std::move(link));
	std::string stop;
	if (!client->Handshake(&stop, &error))
		return {{"error", error}};
	kd_ = std::move(client);
	kd_breakpoints_.clear();
	// VirtualBox 7.2's stub mis-sizes the P value (RTStrConvertHexBytes gets
	// the digit count as the byte count), sends no reply and drops the link;
	// it has no G. Its DBGC console's 'r' prints rip= and sets registers.
	// It also drops the last byte of every qRcmd command (dbgcEvalCommand gets
	// the decoded length - 1: 'r' was an unknown command ''), so DBGC
	// commands get a trailing space.
	kd_dbgc_ = MonitorText(*kd_, "r ").find("rip=") != std::string::npos;
	std::string threads, more;
	kd_->Request("qfThreadInfo", &threads);
	json cpus = json::array();
	for (std::string list = threads; !list.empty() && list[0] == 'm';) {
		size_t at = 1;
		while (at < list.size()) {
			const size_t comma = list.find(',', at);
			cpus.push_back(std::stoi(list.substr(at, comma - at), nullptr, 16) - 1);
			if (comma == std::string::npos)
				break;
			at = comma + 1;
		}
		if (!kd_->Request("qsThreadInfo", &list))
			break;
	}
	return {{"connected", true}, {"halted", true}, {"stop", StopJson(stop)}, {"cpus", cpus},
		{"note", "every CPU is held until veh_kd_continue; veh_kd_disconnect resumes and detaches"}};
}

json McpServer::ToolKdDisconnect(const json&)
{
	if (!kd_)
		return {{"disconnected", true}};
	std::string reply;
	if (kd_->running()) {
		std::string stop;
		if (!kd_->Interrupt(&stop, 5000))
			return {{"error", "Could not stop the target for breakpoint cleanup; session retained"}};
	}
	// The stub's detach keeps DBGF breakpoints: one hit with no debugger
	// attached powers the VM off (DBGF waits for an attach, then EM stops).
	// Remove ours first.
	for (auto it = kd_breakpoints_.begin(); it != kd_breakpoints_.end();) {
		const auto [address, type, size] = *it;
		std::string removed;
		char packet[64];
		snprintf(packet, sizeof(packet), "z%c,%llx,%x", type,
			static_cast<unsigned long long>(address), size);
		if (!kd_->Request(packet, &removed) || removed != "OK")
			return {{"error", "Breakpoint cleanup failed; session retained"}, {"address", HexAddr(address)}};
		it = kd_breakpoints_.erase(it);
	}
	const bool ok = kd_->Request("D", &reply) && reply == "OK";
	kd_.reset();
	kd_breakpoints_.clear();
	return {{"disconnected", true}, {"detached", ok}};
}

json McpServer::ToolKdContinue(const json& args)
{
	if (!kd_)
		return KdNotConnected();
	if (kd_->running())
		return {{"error", "already running: veh_kd_wait or veh_kd_break"}};
	if (!kd_->Resume("c"))
		return {{"error", "link lost"}};
	if (!JsonBool(args, "wait", false))
		return {{"running", true}};
	std::string stop;
	if (!kd_->WaitStop(&stop, JsonUint32(args, "timeout_ms", 10000)))
		return {{"running", true}, {"timeout", true}};
	return {{"running", false}, {"stop", StopJson(stop)}};
}

json McpServer::ToolKdWait(const json& args)
{
	if (!kd_)
		return KdNotConnected();
	std::string stop;
	if (!kd_->WaitStop(&stop, JsonUint32(args, "timeout_ms", 10000)))
		return {{"running", true}, {"timeout", true}};
	return {{"running", false}, {"stop", StopJson(stop)}};
}

json McpServer::ToolKdBreak(const json& args)
{
	if (!kd_)
		return KdNotConnected();
	std::string stop;
	if (!kd_->Interrupt(&stop, JsonUint32(args, "timeout_ms", 10000)))
		return {{"error", "the target did not stop"}, {"diagnostic", kd_->wait_diagnostic()}};
	return {{"running", false}, {"stop", StopJson(stop)}};
}

json McpServer::ToolKdStep(const json& args)
{
	if (!kd_)
		return KdNotConnected();
	if (kd_->running())
		return {{"error", "running: veh_kd_break first"}};
	const uint32_t count = JsonUint32(args, "count", 1);
	std::string stop = kd_->last_stop();
	std::string thread = args.contains("cpu") ? ":" + std::to_string(JsonInt(args, "cpu", 0) + 1) : "";
	if (thread.empty()) {
		const size_t t = stop.find("thread:");
		if (t != std::string::npos)
			thread = ":" + stop.substr(t + 7, stop.find(';', t) - t - 7);
	}
	for (uint32_t i = 0; i < count; ++i) {
		const std::string before = ToolKdRegisters(json::object()).value("rip", "");
		if (!kd_->Resume("vCont;s" + thread))
			return {{"error", "link lost"}, {"steps", i}};
		if (kd_->WaitStop(&stop, JsonUint32(args, "timeout_ms", 10000)))
			continue;
		// Live (VirtualBox DBGC, kd_x64 run 203425): the stub acknowledged the
		// step but sent no stop reply. Ask for the stop reason; the step counts
		// only if the target is halted at a new RIP.
		const std::string diagnostic = kd_->wait_diagnostic();
		if (!kd_->QueryStop(&stop, 3000) || ToolKdRegisters(json::object()).value("rip", "") == before)
			return {{"error", "step did not complete"}, {"steps", i}, {"diagnostic", diagnostic}};
	}
	json regs = ToolKdRegisters(json::object());
	json out = {{"steps", count}, {"stop", StopJson(stop)}, {"rip", regs.value("rip", "")}};
	if (regs.contains("rip")) {
		json mem = ToolKdMemory({{"operation", "disassemble"}, {"address", regs["rip"]}, {"count", 1}});
		if (mem.contains("instructions") && !mem["instructions"].empty())
			out["next"] = mem["instructions"][0];
	}
	return out;
}

json McpServer::ToolKdRegisters(const json& args)
{
	if (!kd_)
		return KdNotConnected();
	if (kd_->running())
		return {{"error", "running: veh_kd_break first"}};
	json error;
	if (!KdSelect(args, error))
		return error;
	std::string reply;
	// The general registers and eflags are required; stubs send a varying
	// number of segment registers after them (VirtualBox: cs and ss).
	if (!kd_->Request("g", &reply) || reply.size() < 2 * (17 * 8 + 4))
		return {{"error", "register read failed"}, {"reply", reply.substr(0, 16)}};
	const auto g = FromHex(reply);
	json out;
	for (size_t i = 0; i < 17; ++i)
		out[kGdbRegs[i]] = HexAddr(Le(g, i * 8, 8));
	out["rflags"] = HexAddr(Le(g, 17 * 8, 4));
	for (size_t i = 0; i < 6 && g.size() >= 17 * 8 + 4 + (i + 1) * 4; ++i)
		out[kGdbSegs[i]] = HexAddr(Le(g, 17 * 8 + 4 + i * 4, 4));
	// System state (stub monitor command), when the stub offers it.
	const std::string extra = MonitorText(*kd_, kd_dbgc_ ? "regs " : "regs");
	for (const char* key : { "cr3", "gs_base", "fs_base", "idt", "cpl" }) {
		const std::string tag = std::string(key) + "=";
		const size_t at = extra.find(tag);
		if (at != std::string::npos)
			out[key] = "0x" + extra.substr(at + tag.size(), extra.find_first_of(" \n", at) - at - tag.size());
	}
	return out;
}

json McpServer::ToolKdSetRegister(const json& args)
{
	if (!kd_)
		return KdNotConnected();
	json error;
	if (!KdSelect(args, error))
		return error;
	const std::string name = args.value("name", "");
	const uint64_t value = ParseHex(args.value("value", "0"));
	int number = -1;
	size_t size = 8;
	for (int i = 0; i < 17; ++i)
		if (name == kGdbRegs[i])
			number = i;
	if (name == "rflags" || name == "eflags") {
		number = 17;
		size = 4;
	}
	if (number < 0)
		return {{"error", "unknown register (rax..r15, rip, rflags)"}};
	if (kd_dbgc_) {
		char command[64];
		snprintf(command, sizeof(command), "r %s = 0x%llx", name == "eflags" ? "rflags" : name.c_str(),
			static_cast<unsigned long long>(value));
		const std::string text = MonitorText(*kd_, std::string(command) + " ");
		std::string reply;
		char read[8];
		snprintf(read, sizeof(read), "p%x", number);
		const auto now = kd_->Request(read, &reply) ? FromHex(reply) : std::vector<uint8_t>{};
		if (now.size() < size || Le(now, 0, size) != (size == 4 ? (value & 0xFFFFFFFFu) : value))
			return {{"error", "register write failed"}, {"console", text}};
		return {{"success", true}, {"name", name}, {"value", HexAddr(value)}};
	}
	std::vector<uint8_t> bytes(size);
	for (size_t i = 0; i < size; ++i)
		bytes[i] = static_cast<uint8_t>(value >> (8 * i));
	char head[16];
	snprintf(head, sizeof(head), "P%x=", number);
	std::string reply;
	if (!kd_->Request(head + HexBytes(bytes), &reply) || reply != "OK")
		return {{"error", "register write failed"}, {"reply", reply}};
	return {{"success", true}, {"name", name}, {"value", HexAddr(value)}};
}

json McpServer::ToolKdMemory(const json& args)
{
	if (!kd_)
		return KdNotConnected();
	if (kd_->running())
		return {{"error", "running: veh_kd_break first"}};
	json error;
	if (!KdSelect(args, error))
		return error;
	const std::string op = args.value("operation", "read");
	const uint64_t address = ParseHex(args.value("address", "0"));
	std::string reply;
	if (op == "write") {
		const auto data = FromHex(args.value("data", ""));
		if (data.empty())
			return {{"error", "data required (hex bytes)"}};
		for (size_t at = 0; at < data.size(); at += 0x7F0) {
			const std::vector<uint8_t> chunk(data.begin() + at, data.begin() + (std::min)(data.size(), at + 0x7F0));
			char head[48];
			snprintf(head, sizeof(head), "M%llx,%zx:", static_cast<unsigned long long>(address + at), chunk.size());
			if (!kd_->Request(head + HexBytes(chunk), &reply) || reply != "OK")
				return {{"error", "write failed"}, {"address", HexAddr(address + at)}, {"reply", reply}};
		}
		return {{"success", true}, {"address", HexAddr(address)}, {"size", data.size()}};
	}
	const bool disasm = op == "disassemble";
	const uint32_t count = JsonUint32(args, "count", 16);
	size_t size = disasm ? count * 15 : JsonUint32(args, "size", 64);
	if (size > 0x10000)
		size = 0x10000;
	std::vector<uint8_t> data;
	for (size_t at = 0; at < size;) {
		const size_t n = (std::min)(size - at, static_cast<size_t>(0x7F0));
		char head[48];
		snprintf(head, sizeof(head), "m%llx,%zx", static_cast<unsigned long long>(address + at), n);
		if (!kd_->Request(head, &reply) || reply.empty() || (reply.size() == 3 && reply[0] == 'E')) {
			if (data.empty())
				return {{"error", "unreadable"}, {"address", HexAddr(address + at)}, {"reply", reply}};
			break; // a readable prefix
		}
		const auto chunk = FromHex(reply);
		data.insert(data.end(), chunk.begin(), chunk.end());
		at += n;
	}
	if (!disasm)
		return {{"address", HexAddr(address)}, {"size", data.size()}, {"hex", HexBytes(data)}};
	ZydisDisassembler decoder(true);
	json list = json::array();
	for (auto& insn : decoder.Disassemble(data.data(), static_cast<uint32_t>(data.size()), address, count))
		list.push_back({{"address", HexAddr(insn.address)}, {"bytes", insn.bytes}, {"text", insn.mnemonic}});
	return {{"address", HexAddr(address)}, {"instructions", list}};
}

json McpServer::ToolKdBreakpoint(const json& args)
{
	if (!kd_)
		return KdNotConnected();
	const std::string action = args.value("action", "list");
	if (action == "list") {
		json list = json::array();
		std::set<uint64_t> addresses;
		for (const auto& bp : kd_breakpoints_) addresses.insert(std::get<0>(bp));
		for (uint64_t address : addresses) list.push_back(HexAddr(address));
		return {{"breakpoints", list}};
	}
	if (kd_->running())
		return {{"error", "running: veh_kd_break first"}};
	const uint64_t address = ParseHex(args.value("address", "0"));
	const std::string kind = args.value("kind", "execute");
	const char type = kind == "write" ? '2' : kind == "read" ? '3' : kind == "access" ? '4' : '0';
	const uint32_t size = type == '0' ? 1 : JsonUint32(args, "size", 1);
	char packet[64];
	snprintf(packet, sizeof(packet), "%c%c,%llx,%x", action == "remove" ? 'z' : 'Z', type,
		static_cast<unsigned long long>(address), size);
	std::string reply;
	// Live (VirtualBox DBGC, kd_x64 run 210451): a z0 right after a breakpoint
	// stop got no answer within 5 s while the console was still reporting the
	// event. Z/z are idempotent: ask once more.
	if (!kd_->Request(packet, &reply) && !kd_->Request(packet, &reply, 10000))
		return {{"error", "no answer"}, {"trace", kd_->trace()}};
	if (reply.empty())
		return {{"error", "breakpoints not supported by this stub"}};
	if (reply != "OK")
		return {{"error", "rejected (address not mapped?)"}, {"reply", reply}};
	if (action == "remove")
		kd_breakpoints_.erase(std::make_tuple(address, type, size));
	else
		kd_breakpoints_.insert(std::make_tuple(address, type, size));
	return {{"success", true}, {"action", action == "remove" ? "remove" : "add"}, {"address", HexAddr(address)},
		{"kind", kind}};
}

json McpServer::ToolKdMonitor(const json& args)
{
	if (!kd_)
		return KdNotConnected();
	if (kd_->running())
		return {{"error", "running: veh_kd_break first"}};
	const std::string text = MonitorText(*kd_, args.value("command", "help") + (kd_dbgc_ ? " " : ""));
	return {{"output", text}};
}

} // namespace veh
