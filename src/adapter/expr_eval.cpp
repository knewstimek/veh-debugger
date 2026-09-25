#include "expr_eval.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <optional>
#include <sstream>
#include <utility>
#include <vector>

namespace veh {
namespace {

const char* kSupportedExpressions =
	"Supported: register (RAX), 0x<addr>, [addr], [reg+offset], gs:[offset], fs:[offset]";

std::string TrimSpaces(std::string value) {
	while (!value.empty() && value.front() == ' ') value.erase(value.begin());
	while (!value.empty() && value.back() == ' ') value.pop_back();
	return value;
}

std::optional<RegisterSet> ReadRegisters(IIpcTransport& transport, uint32_t threadId,
	ExprEvalFrontend frontend) {
	GetRegistersRequest request{};
	request.threadId = threadId;

	std::vector<uint8_t> response;
	if (!transport.SendAndReceive(IpcCommand::GetRegisters, &request, sizeof(request), response)
		|| response.size() < sizeof(GetRegistersResponse))
		return std::nullopt;

	auto* registers = reinterpret_cast<const GetRegistersResponse*>(response.data());
	if (frontend == ExprEvalFrontend::Mcp && registers->status != IpcStatus::Ok)
		return std::nullopt;
	return registers->regs;
}

uint32_t GetPointerSize(HANDLE targetProcess) {
	BOOL wow64 = FALSE;
	if (targetProcess) IsWow64Process(targetProcess, &wow64);
	return wow64 ? 4 : 8;
}

bool ReadPointer(IIpcTransport& transport, uint64_t address, uint32_t pointerSize,
	uint64_t& value) {
	ReadMemoryRequest request{};
	request.address = address;
	request.size = pointerSize;

	std::vector<uint8_t> response;
	if (!transport.SendAndReceive(IpcCommand::ReadMemory, &request, sizeof(request), response)
		|| response.size() < sizeof(IpcStatus) + pointerSize
		|| *reinterpret_cast<const IpcStatus*>(response.data()) != IpcStatus::Ok)
		return false;

	value = 0;
	memcpy(&value, response.data() + sizeof(IpcStatus), pointerSize);
	return true;
}

std::string FormatPointer(uint64_t value, uint32_t pointerSize) {
	char buffer[24];
	snprintf(buffer, sizeof(buffer), pointerSize == 4 ? "0x%08llX" : "0x%016llX", value);
	return buffer;
}

ExprEvalResult Failure(ExprEvalFrontend frontend, const std::string& mcpError) {
	ExprEvalResult result;
	result.error = frontend == ExprEvalFrontend::Dap ? kSupportedExpressions : mcpError;
	return result;
}

bool ParseNumber(const std::string& text, uint64_t& value, ExprEvalFrontend frontend) {
	if (text.empty()) return false;
	try {
		size_t position = 0;
		value = std::stoull(text, &position, 0);
		return frontend == ExprEvalFrontend::Dap || position == text.size();
	} catch (...) {
		return false;
	}
}

} // namespace

bool TryParseExpressionRegister(const std::string& name) {
	std::string upper = name;
	if (!upper.empty() && upper[0] == '$') upper = upper.substr(1);
	std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
	static const char* registerNames[] = {
		"RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
		"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
		"RIP", "RFLAGS",
		"EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP",
		"EIP", "EFLAGS",
	};
	for (auto* registerName : registerNames) {
		if (upper == registerName) return true;
	}
	return false;
}

uint64_t ResolveExpressionRegister(const std::string& name, const RegisterSet& regs,
	ExprEvalFrontend frontend) {
	std::string upper = name;
	if (!upper.empty() && upper[0] == '$') upper = upper.substr(1);
	std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
	const uint64_t* registers = &regs.rax;
	static const std::pair<const char*, int> registerMap[] = {
		{"RAX",0},{"EAX",0},{"RBX",1},{"EBX",1},{"RCX",2},{"ECX",2},{"RDX",3},{"EDX",3},
		{"RSI",4},{"ESI",4},{"RDI",5},{"EDI",5},{"RBP",6},{"EBP",6},{"RSP",7},{"ESP",7},
		{"R8",8},{"R9",9},{"R10",10},{"R11",11},{"R12",12},{"R13",13},{"R14",14},{"R15",15},
		{"RIP",16},{"EIP",16},{"RFLAGS",17},{"EFLAGS",17},
	};
	for (auto& [registerName, index] : registerMap) {
		if (upper == registerName) {
			uint64_t value = registers[index];
			if (frontend == ExprEvalFrontend::Mcp && upper[0] == 'E' && upper != "EFLAGS")
				value &= 0xFFFFFFFF;
			return value;
		}
	}
	return 0;
}

bool ResolveExpressionAddress(const std::string& expression, const RegisterSet* regs,
	uint64_t& address, ExprEvalFrontend frontend) {
	std::string inner = TrimSpaces(expression);
	if (inner.empty()) return false;

	if (ParseNumber(inner, address, frontend)) return true;

	size_t operatorPosition = std::string::npos;
	char operation = 0;
	for (size_t i = 1; i < inner.size(); i++) {
		if (inner[i] == '+' || inner[i] == '-') {
			operatorPosition = i;
			operation = inner[i];
			break;
		}
	}
	if (operatorPosition != std::string::npos) {
		std::string lhs = inner.substr(0, operatorPosition);
		std::string rhs = inner.substr(operatorPosition + 1);
		while (!lhs.empty() && lhs.back() == ' ') lhs.pop_back();
		while (!rhs.empty() && rhs.front() == ' ') rhs.erase(rhs.begin());

		uint64_t lhsValue = 0;
		uint64_t rhsValue = 0;
		bool lhsOk = false;
		bool rhsOk = false;
		if (TryParseExpressionRegister(lhs)) {
			if (regs) {
				lhsValue = ResolveExpressionRegister(lhs, *regs, frontend);
				lhsOk = true;
			}
		} else {
			lhsOk = ParseNumber(lhs, lhsValue, frontend);
		}
		if (TryParseExpressionRegister(rhs)) {
			if (regs) {
				rhsValue = ResolveExpressionRegister(rhs, *regs, frontend);
				rhsOk = true;
			}
		} else {
			rhsOk = ParseNumber(rhs, rhsValue, frontend);
		}

		if (!lhsOk || !rhsOk) return false;
		if (operation == '+') {
			uint64_t sum = lhsValue + rhsValue;
			if (frontend == ExprEvalFrontend::Mcp && sum < lhsValue) return false;
			address = sum;
		} else {
			if (frontend == ExprEvalFrontend::Mcp && rhsValue > lhsValue) return false;
			address = lhsValue - rhsValue;
		}
		return true;
	}

	if (TryParseExpressionRegister(inner)) {
		if (!regs) return false;
		address = ResolveExpressionRegister(inner, *regs, frontend);
		return true;
	}
	return false;
}

ExprEvalResult EvaluateExpression(IIpcTransport& transport, HANDLE targetProcess,
	const std::string& expression, uint32_t threadId, ExprEvalFrontend frontend) {
	const uint32_t pointerSize = GetPointerSize(targetProcess);
	std::string expr = TrimSpaces(expression);

	if (TryParseExpressionRegister(expr)) {
		if (frontend == ExprEvalFrontend::Mcp && threadId == 0)
			return Failure(frontend, "threadId is required for register evaluation");
		auto regs = ReadRegisters(transport, threadId, frontend);
		if (!regs) return Failure(frontend, "Failed to read registers");

		uint64_t value = ResolveExpressionRegister(expr, *regs, frontend);
		char buffer[32];
		if (regs->is32bit)
			snprintf(buffer, sizeof(buffer), "0x%08X", static_cast<uint32_t>(value));
		else
			snprintf(buffer, sizeof(buffer), "0x%016llX", value);
		ExprEvalResult result;
		result.ok = true;
		result.value = buffer;
		result.type = regs->is32bit ? "uint32" : "uint64";
		return result;
	}

	if (expr.size() > 2 && expr[0] == '0' && (expr[1] == 'x' || expr[1] == 'X')) {
		try {
			uint64_t address = std::stoull(expr, nullptr, 16);
			uint64_t value = 0;
			if (ReadPointer(transport, address, pointerSize, value)) {
				char buffer[32];
				snprintf(buffer, sizeof(buffer), "[0x%llX] = ", address);
				ExprEvalResult result;
				result.ok = true;
				result.value = buffer + FormatPointer(value, pointerSize);
				result.type = "memory";
				return result;
			}
		} catch (...) {}
		return Failure(frontend, "Failed to read memory at " + expr);
	}

	{
		std::string upper = expr;
		std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
		bool isGs = upper.substr(0, 4) == "GS:[";
		bool isFs = upper.substr(0, 4) == "FS:[";
		if (isGs || isFs) {
			std::string offsetText = expr.substr(4);
			if (!offsetText.empty() && offsetText.back() == ']') offsetText.pop_back();
			while (!offsetText.empty() && offsetText.front() == ' ') offsetText.erase(offsetText.begin());
			try {
				uint64_t offset = std::stoull(offsetText, nullptr, 0);
				if (frontend == ExprEvalFrontend::Mcp && threadId == 0)
					return Failure(frontend, "threadId is required for segment register evaluation");

				HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
				if (!thread) return Failure(frontend, "Failed to open thread");

				typedef struct {
					LONG ExitStatus;
					PVOID TebBaseAddress;
					struct { HANDLE UniqueProcess; HANDLE UniqueThread; } ClientId;
					ULONG_PTR AffinityMask;
					LONG Priority;
					LONG BasePriority;
				} THREAD_BASIC_INFORMATION;
				typedef LONG(NTAPI* NtQueryInformationThread_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
				auto queryThread = reinterpret_cast<NtQueryInformationThread_t>(
					GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
				if (!queryThread) {
					CloseHandle(thread);
					return Failure(frontend, "NtQueryInformationThread not found");
				}

				BOOL wow64 = FALSE;
				IsWow64Process(targetProcess ? targetProcess : GetCurrentProcess(), &wow64);
				if ((!wow64 && isFs) || (wow64 && isGs)) {
					CloseHandle(thread);
					return Failure(frontend, isFs
						? "fs:[] is x86 only (use gs:[] for x64)"
						: "gs:[] is x64 only (use fs:[] for x86)");
				}

				THREAD_BASIC_INFORMATION threadInfo{};
				LONG status = queryThread(thread, 0, &threadInfo, sizeof(threadInfo), nullptr);
				CloseHandle(thread);
				if (status != 0) return Failure(frontend, "NtQueryInformationThread failed");

				uint64_t tebAddress = reinterpret_cast<uint64_t>(threadInfo.TebBaseAddress);
				uint64_t value = 0;
				if (ReadPointer(transport, tebAddress + offset, pointerSize, value)) {
					char buffer[64];
					snprintf(buffer, sizeof(buffer), " (TEB=0x%llX + 0x%llX)", tebAddress, offset);
					ExprEvalResult result;
					result.ok = true;
					result.value = FormatPointer(value, pointerSize) + buffer;
					result.type = "segment";
					result.tebAddress = (std::ostringstream() << "0x" << std::hex << tebAddress).str();
					return result;
				}
				return Failure(frontend, "Failed to read memory at segment base + offset");
			} catch (...) {}
			return Failure(frontend, "Invalid offset in segment expression");
		}
	}

	if (!expr.empty() && (expr[0] == '*' || expr[0] == '[')) {
		std::string inner = expr.substr(1);
		if (!inner.empty() && inner.back() == ']') inner.pop_back();
		inner = TrimSpaces(inner);

		uint64_t address = 0;
		bool resolved = ResolveExpressionAddress(inner, nullptr, address, frontend);
		if (!resolved && threadId != 0) {
			auto regs = ReadRegisters(transport, threadId, frontend);
			if (regs) resolved = ResolveExpressionAddress(inner, &*regs, address, frontend);
		}
		if (!resolved) return Failure(frontend, "Cannot parse address expression: " + inner);

		uint64_t value = 0;
		if (ReadPointer(transport, address, pointerSize, value)) {
			ExprEvalResult result;
			result.ok = true;
			result.value = FormatPointer(value, pointerSize);
			result.type = frontend == ExprEvalFrontend::Dap
				? (pointerSize == 4 ? "uint32" : "uint64")
				: "pointer";
			result.address = address;
			return result;
		}
		ExprEvalResult result = Failure(frontend, "Failed to read memory at computed address");
		result.address = address;
		return result;
	}

	return Failure(frontend, kSupportedExpressions);
}

} // namespace veh
