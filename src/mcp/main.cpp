#include "mcp_server.h"
#include "installer.h"
#include "adapter/transport.h"
#include "common/logger.h"
#include <cstdio>
#include <string>
#include <vector>
#include <algorithm>

void PrintUsage() {
	fprintf(stderr,
		"VEH MCP Server - MCP tool server for VEH Debugger\n"
		"\n"
		"Usage:\n"
		"  veh-mcp-server [options]\n"
		"\n"
		"Options:\n"
		"  --install [AGENT]    Install to AI agent config (auto-detect or specify)\n"
		"  --uninstall [AGENT]  Uninstall from AI agent config\n"
		"  --log=FILE           Log to file\n"
		"  --log-level=LEVEL    Log level: debug, info, warn, error (default: info)\n"
		"  --help               Show this help\n"
		"\n"
		"Agents: claude-code, claude-desktop, cursor, windsurf, codex, all\n"
		"\n"
		"Examples:\n"
		"  veh-mcp-server --install              # Install to all detected agents\n"
		"  veh-mcp-server --install claude-code   # Install to Claude Code only\n"
		"  veh-mcp-server --uninstall             # Uninstall from all agents\n"
		"\n"
		"This server communicates via stdin/stdout using MCP (JSON-RPC 2.0).\n"
	);
}

int HandleInstall(const std::string& targetAgent) {
	std::string selfPath = veh::GetSelfPath();
	if (selfPath.empty()) {
		fprintf(stderr, "Error: cannot determine own executable path\n");
		return 1;
	}

	auto agents = veh::DetectAgents();

	fprintf(stderr, "VEH MCP Server Installer\n");
	fprintf(stderr, "Server: %s\n\n", selfPath.c_str());

	bool anyInstalled = false;

	for (auto& agent : agents) {
		// 특정 에이전트 지정 시 필터링
		if (!targetAgent.empty() && targetAgent != "all" && targetAgent != agent.name) {
			continue;
		}

		// "all"이거나 미지정일 때는 전체 설치
		fprintf(stderr, "  %-18s ", agent.displayName.c_str());

		if (agent.installed) {
			fprintf(stderr, "[already installed]\n");
			anyInstalled = true;
			continue;
		}

		if (veh::InstallToAgent(agent, selfPath)) {
			fprintf(stderr, "[installed] -> %s\n", agent.configPath.c_str());
			anyInstalled = true;
		} else {
			fprintf(stderr, "[FAILED] -> %s\n", agent.configPath.c_str());
		}
	}

	if (!anyInstalled && !targetAgent.empty() && targetAgent != "all") {
		fprintf(stderr, "  Unknown agent: %s\n", targetAgent.c_str());
		fprintf(stderr, "  Available: claude-code, claude-desktop, cursor, windsurf, codex, all\n");
		return 1;
	}

	fprintf(stderr, "\nDone. Restart your AI agent/IDE to activate.\n");
	return 0;
}

int HandleUninstall(const std::string& targetAgent) {
	auto agents = veh::DetectAgents();

	fprintf(stderr, "VEH MCP Server Uninstaller\n\n");

	for (auto& agent : agents) {
		if (!targetAgent.empty() && targetAgent != "all" && targetAgent != agent.name) {
			continue;
		}

		fprintf(stderr, "  %-18s ", agent.displayName.c_str());

		if (!agent.installed) {
			fprintf(stderr, "[not installed]\n");
			continue;
		}

		if (veh::UninstallFromAgent(agent)) {
			fprintf(stderr, "[uninstalled]\n");
		} else {
			fprintf(stderr, "[FAILED]\n");
		}
	}

	fprintf(stderr, "\nDone.\n");
	return 0;
}

int main(int argc, char* argv[]) {
	std::string logFile;
	veh::LogLevel logLevel = veh::LogLevel::Info;
	bool doInstall = false;
	bool doUninstall = false;
	std::string targetAgent;

	for (int i = 1; i < argc; i++) {
		std::string arg = argv[i];

		if (arg == "--install") {
			doInstall = true;
			// 다음 인자가 에이전트 이름인지 확인
			if (i + 1 < argc && argv[i + 1][0] != '-') {
				targetAgent = argv[++i];
			}
		} else if (arg == "--uninstall") {
			doUninstall = true;
			if (i + 1 < argc && argv[i + 1][0] != '-') {
				targetAgent = argv[++i];
			}
		} else if (arg.substr(0, 6) == "--log=") {
			logFile = arg.substr(6);
		} else if (arg.substr(0, 12) == "--log-level=") {
			std::string level = arg.substr(12);
			if (level == "debug")      logLevel = veh::LogLevel::Debug;
			else if (level == "info")  logLevel = veh::LogLevel::Info;
			else if (level == "warn")  logLevel = veh::LogLevel::Warning;
			else if (level == "error") logLevel = veh::LogLevel::Error;
		} else if (arg == "--help" || arg == "-h") {
			PrintUsage();
			return 0;
		} else {
			fprintf(stderr, "Unknown option: %s\n", arg.c_str());
			PrintUsage();
			return 1;
		}
	}

	// Install/Uninstall 모드
	if (doInstall) return HandleInstall(targetAgent);
	if (doUninstall) return HandleUninstall(targetAgent);

	// 로깅 설정
	veh::Logger::Instance().SetLevel(logLevel);
	if (!logFile.empty()) {
		veh::Logger::Instance().SetFile(logFile);
	}

	LOG_INFO("VEH MCP Server starting");

	// MCP는 항상 stdin/stdout (StdioTransport)
	veh::dap::StdioTransport transport;
	veh::McpServer server;
	server.SetTransport(&transport);

	server.Run();

	LOG_INFO("VEH MCP Server exiting");
	return 0;
}
