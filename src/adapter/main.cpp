#include "dap_server.h"
#include "transport.h"
#include "logger.h"
#include <cstdio>
#include <cstring>
#include <string>

void PrintUsage() {
	fprintf(stderr,
		"VEH Debug Adapter - DAP server for VEH Debugger\n"
		"\n"
		"Usage:\n"
		"  veh-debug-adapter [options]\n"
		"\n"
		"Options:\n"
		"  --tcp              Use TCP transport instead of stdin/stdout\n"
		"  --port=PORT        TCP port (default: 4711)\n"
		"  --remote           Bind to 0.0.0.0 (allow remote connections)\n"
		"  --bind=0.0.0.0     Same as --remote\n"
		"  --log=FILE         Log to file\n"
		"  --log-level=LEVEL  Log level: debug, info, warn, error (default: info)\n"
		"  --help             Show this help\n"
		"\n"
		"Examples:\n"
		"  veh-debug-adapter                              # stdio mode (VSCode)\n"
		"  veh-debug-adapter --tcp --port=4711            # TCP local only\n"
		"  veh-debug-adapter --tcp --port=4711 --remote   # TCP remote (VM/network)\n"
	);
}

int main(int argc, char* argv[]) {
	bool useTcp = false;
	bool allowRemote = false;
	uint16_t port = 4711;
	std::string logFile;
	veh::LogLevel logLevel = veh::LogLevel::Info;

	// 커맨드라인 파싱
	for (int i = 1; i < argc; i++) {
		std::string arg = argv[i];

		if (arg == "--tcp") {
			useTcp = true;
		} else if (arg.substr(0, 7) == "--port=") {
			try {
				int p = std::stoi(arg.substr(7));
				if (p < 1 || p > 65535) {
					fprintf(stderr, "Invalid port: %d\n", p);
					return 1;
				}
				port = (uint16_t)p;
			} catch (...) {
				fprintf(stderr, "Invalid port value\n");
				return 1;
			}
		} else if (arg == "--bind=0.0.0.0" || arg == "--remote") {
			allowRemote = true;
		} else if (arg.substr(0, 6) == "--log=") {
			logFile = arg.substr(6);
		} else if (arg.substr(0, 12) == "--log-level=") {
			std::string level = arg.substr(12);
			if (level == "debug") logLevel = veh::LogLevel::Debug;
			else if (level == "info") logLevel = veh::LogLevel::Info;
			else if (level == "warn") logLevel = veh::LogLevel::Warning;
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

	// 로거 설정
	veh::Logger::Instance().SetLevel(logLevel);
	if (!logFile.empty()) {
		veh::Logger::Instance().SetFile(logFile);
	}

	LOG_INFO("VEH Debug Adapter starting (mode: %s)", useTcp ? "TCP" : "stdio");

	// Transport 생성
	std::unique_ptr<veh::dap::Transport> transport;
	if (useTcp) {
		transport = std::make_unique<veh::dap::TcpTransport>(port, allowRemote);
		if (allowRemote) {
			LOG_WARN("Remote access enabled (0.0.0.0) - ensure firewall is configured!");
		}
	} else {
		transport = std::make_unique<veh::dap::StdioTransport>();
	}

	// DAP 서버 실행
	veh::dap::DapServer server;
	server.SetTransport(transport.get());
	server.Run();

	LOG_INFO("VEH Debug Adapter exiting");
	return 0;
}
