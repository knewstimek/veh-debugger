#pragma once

#include <windows.h>
#include <cstdint>
#include <string>

#include "ipc_transport.h"

namespace veh {

enum class ExprEvalFrontend {
	Mcp,
	Dap,
};

struct ExprEvalResult {
	bool ok = false;
	std::string value;
	std::string type;
	uint64_t address = 0;
	std::string tebAddress;
	std::string error;
};

ExprEvalResult EvaluateExpression(IIpcTransport& transport, HANDLE targetProcess,
	const std::string& expression, uint32_t threadId, ExprEvalFrontend frontend);

bool TryParseExpressionRegister(const std::string& name);
uint64_t ResolveExpressionRegister(const std::string& name, const RegisterSet& regs,
	ExprEvalFrontend frontend);
bool ResolveExpressionAddress(const std::string& expression, const RegisterSet* regs,
	uint64_t& address, ExprEvalFrontend frontend);

} // namespace veh
