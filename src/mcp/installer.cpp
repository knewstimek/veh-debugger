#include "installer.h"
#include <nlohmann/json.hpp>
#include <windows.h>
#include <shlobj.h>
#include <fstream>
#include <sstream>
#include <cstdio>
#include <filesystem>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace veh {

static const char* SERVER_NAME = "veh-debugger";

// %USERPROFILE% 경로 반환
static std::string GetHomePath() {
	char path[MAX_PATH];
	if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, path))) {
		return std::string(path);
	}
	// 폴백
	const char* home = getenv("USERPROFILE");
	return home ? home : "C:\\Users\\Default";
}

// %APPDATA% 경로 반환
static std::string GetAppDataPath() {
	char path[MAX_PATH];
	if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path))) {
		return std::string(path);
	}
	return GetHomePath() + "\\AppData\\Roaming";
}

// 경로 구분자를 슬래시로 통일
static std::string NormalizePath(const std::string& path) {
	std::string result = path;
	for (char& c : result) {
		if (c == '\\') c = '/';
	}
	return result;
}

// JSON 파일 읽기
static json ReadJsonFile(const std::string& path) {
	std::ifstream f(path);
	if (!f.is_open()) return json::object();
	try {
		return json::parse(f);
	} catch (...) {
		return json::object();
	}
}

// JSON 파일 쓰기 (pretty print)
static bool WriteJsonFile(const std::string& path, const json& data) {
	// 부모 디렉토리 생성
	fs::path p(path);
	if (p.has_parent_path()) {
		std::error_code ec;
		fs::create_directories(p.parent_path(), ec);
	}

	std::ofstream f(path);
	if (!f.is_open()) return false;
	f << data.dump(2) << std::endl;
	return f.good();
}

// JSON 설정 파일에서 mcpServers.veh-debugger 존재 여부 확인
static bool IsInstalledJson(const std::string& path) {
	json data = ReadJsonFile(path);
	return data.contains("mcpServers") &&
	       data["mcpServers"].contains(SERVER_NAME);
}

// JSON 설정 파일에 mcpServers.veh-debugger 등록
static bool InstallJson(const std::string& path, const std::string& serverPath) {
	json data = ReadJsonFile(path);

	if (!data.contains("mcpServers")) {
		data["mcpServers"] = json::object();
	}

	data["mcpServers"][SERVER_NAME] = {
		{"command", NormalizePath(serverPath)},
		{"args", json::array({"--log=veh-mcp.log"})}
	};

	return WriteJsonFile(path, data);
}

// JSON 설정 파일에서 mcpServers.veh-debugger 제거
static bool UninstallJson(const std::string& path) {
	json data = ReadJsonFile(path);
	if (!data.contains("mcpServers")) return true;
	data["mcpServers"].erase(SERVER_NAME);
	return WriteJsonFile(path, data);
}

// TOML 파일에서 mcp_servers.veh-debugger 존재 여부 확인
static bool IsInstalledToml(const std::string& path) {
	std::ifstream f(path);
	if (!f.is_open()) return false;
	std::string line;
	std::string target = "[mcp_servers.";
	target += SERVER_NAME;
	target += "]";
	while (std::getline(f, line)) {
		if (line.find(target) != std::string::npos) return true;
	}
	return false;
}

// TOML 파일에 mcp_servers.veh-debugger 등록
static bool InstallToml(const std::string& path, const std::string& serverPath) {
	// 기존 내용 읽기
	std::string content;
	{
		std::ifstream f(path);
		if (f.is_open()) {
			std::ostringstream ss;
			ss << f.rdbuf();
			content = ss.str();
		}
	}

	// 이미 있으면 섹션 교체, 없으면 추가
	std::string section = "[mcp_servers.";
	section += SERVER_NAME;
	section += "]";

	std::string newBlock = section + "\n";
	newBlock += "command = \"" + NormalizePath(serverPath) + "\"\n";
	newBlock += "args = [\"--log=veh-mcp.log\"]\n";
	newBlock += "enabled = true\n";

	auto pos = content.find(section);
	if (pos != std::string::npos) {
		// 기존 섹션을 다음 [섹션] 또는 EOF까지 교체
		auto nextSection = content.find("\n[", pos + 1);
		if (nextSection == std::string::npos) {
			content = content.substr(0, pos) + newBlock;
		} else {
			content = content.substr(0, pos) + newBlock + "\n" + content.substr(nextSection + 1);
		}
	} else {
		if (!content.empty() && content.back() != '\n') content += "\n";
		content += "\n" + newBlock;
	}

	// 부모 디렉토리 생성
	fs::path p(path);
	if (p.has_parent_path()) {
		std::error_code ec;
		fs::create_directories(p.parent_path(), ec);
	}

	std::ofstream f(path);
	if (!f.is_open()) return false;
	f << content;
	return f.good();
}

// TOML 파일에서 mcp_servers.veh-debugger 제거
static bool UninstallToml(const std::string& path) {
	std::ifstream fin(path);
	if (!fin.is_open()) return true;

	std::string content;
	{
		std::ostringstream ss;
		ss << fin.rdbuf();
		content = ss.str();
	}
	fin.close();

	std::string section = "[mcp_servers.";
	section += SERVER_NAME;
	section += "]";

	auto pos = content.find(section);
	if (pos == std::string::npos) return true;

	auto nextSection = content.find("\n[", pos + 1);
	if (nextSection == std::string::npos) {
		content = content.substr(0, pos);
	} else {
		content = content.substr(0, pos) + content.substr(nextSection + 1);
	}

	// 끝 공백 정리
	while (!content.empty() && (content.back() == '\n' || content.back() == '\r')) {
		content.pop_back();
	}
	content += "\n";

	std::ofstream fout(path);
	if (!fout.is_open()) return false;
	fout << content;
	return fout.good();
}

std::vector<AgentConfig> DetectAgents() {
	std::string home = GetHomePath();
	std::string appData = GetAppDataPath();

	std::vector<AgentConfig> agents;

	// Claude Code
	{
		AgentConfig a;
		a.name = "claude-code";
		a.displayName = "Claude Code";
		a.configPath = home + "\\.claude\\settings.json";
		a.exists = fs::exists(a.configPath);
		a.installed = a.exists && IsInstalledJson(a.configPath);
		agents.push_back(a);
	}

	// Claude Desktop
	{
		AgentConfig a;
		a.name = "claude-desktop";
		a.displayName = "Claude Desktop";
		a.configPath = appData + "\\Claude\\claude_desktop_config.json";
		a.exists = fs::exists(a.configPath);
		a.installed = a.exists && IsInstalledJson(a.configPath);
		agents.push_back(a);
	}

	// Cursor
	{
		AgentConfig a;
		a.name = "cursor";
		a.displayName = "Cursor";
		a.configPath = home + "\\.cursor\\mcp.json";
		a.exists = fs::exists(a.configPath);
		a.installed = a.exists && IsInstalledJson(a.configPath);
		agents.push_back(a);
	}

	// Windsurf
	{
		AgentConfig a;
		a.name = "windsurf";
		a.displayName = "Windsurf";
		a.configPath = home + "\\.codeium\\windsurf\\mcp_config.json";
		a.exists = fs::exists(a.configPath);
		a.installed = a.exists && IsInstalledJson(a.configPath);
		agents.push_back(a);
	}

	// Codex CLI (TOML)
	{
		AgentConfig a;
		a.name = "codex";
		a.displayName = "Codex CLI";
		a.configPath = home + "\\.codex\\config.toml";
		a.exists = fs::exists(a.configPath);
		a.installed = a.exists && IsInstalledToml(a.configPath);
		agents.push_back(a);
	}

	return agents;
}

bool InstallToAgent(const AgentConfig& agent, const std::string& serverPath) {
	if (agent.name == "codex") {
		return InstallToml(agent.configPath, serverPath);
	}
	return InstallJson(agent.configPath, serverPath);
}

bool UninstallFromAgent(const AgentConfig& agent) {
	if (agent.name == "codex") {
		return UninstallToml(agent.configPath);
	}
	return UninstallJson(agent.configPath);
}

std::string GetSelfPath() {
	char path[MAX_PATH];
	DWORD len = GetModuleFileNameA(NULL, path, MAX_PATH);
	if (len == 0 || len >= MAX_PATH) return "";
	return std::string(path, len);
}

} // namespace veh
