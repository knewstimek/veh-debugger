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
static const char* PERM_WILDCARD = "mcp__veh-debugger__*";

// %USERPROFILE% 경로 반환
static std::string GetHomePath() {
	char path[MAX_PATH];
	if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, path))) {
		return std::string(path);
	}
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

// --- Claude CLI 방식 ---

// PATH에서 claude 실행파일 찾기
static std::string FindClaudeCLI() {
	// claude.exe, claude.cmd, claude 순서로 탐색
	const char* names[] = {"claude.exe", "claude.cmd", "claude"};
	char result[MAX_PATH];

	for (auto name : names) {
		DWORD len = SearchPathA(NULL, name, NULL, MAX_PATH, result, NULL);
		if (len > 0 && len < MAX_PATH) {
			return std::string(result, len);
		}
	}
	return "";
}

// claude mcp add --scope user 로 등록
static bool InstallClaudeMCPAdd(const std::string& claudePath, const std::string& serverPath) {
	std::string normalizedPath = NormalizePath(serverPath);

	// 기존 등록 제거 (업데이트 지원)
	// _popen → cmd /c 사용하므로 전체를 바깥 따옴표로 감싸야 함
	{
		std::string removeCmd = "\"\"" + claudePath + "\" mcp remove " + SERVER_NAME + "\"";
		FILE* pipe = _popen(removeCmd.c_str(), "r");
		if (pipe) _pclose(pipe);  // 실패 무시
	}

	// --scope user 로 global 등록
	std::string addCmd = "\"\"" + claudePath + "\" mcp add --scope user " +
	                     SERVER_NAME + " \"" + normalizedPath + "\"\"";
	FILE* pipe = _popen(addCmd.c_str(), "r");
	if (!pipe) return false;

	char buf[256];
	std::string output;
	while (fgets(buf, sizeof(buf), pipe)) {
		output += buf;
	}
	int exitCode = _pclose(pipe);

	if (exitCode != 0) {
		printf("  [Claude Code] claude mcp add failed: %s\n", output.c_str());
		return false;
	}

	return true;
}

// ~/.claude.json 의 프로젝트별 mcpServers 경로 업데이트
static void UpdateClaudeProjectMCPServers(const std::string& newPath) {
	std::string claudeJsonPath = GetHomePath() + "\\.claude.json";
	json config = ReadJsonFile(claudeJsonPath);

	if (!config.contains("projects") || !config["projects"].is_object()) {
		return;
	}

	bool modified = false;
	for (auto& [projPath, projConfig] : config["projects"].items()) {
		if (!projConfig.is_object()) continue;
		if (!projConfig.contains("mcpServers")) continue;
		auto& servers = projConfig["mcpServers"];
		if (!servers.is_object() || !servers.contains(SERVER_NAME)) continue;

		auto& entry = servers[SERVER_NAME];
		if (entry.is_object() && entry.contains("command")) {
			std::string oldCmd = entry["command"].get<std::string>();
			if (oldCmd != newPath) {
				entry["command"] = newPath;
				modified = true;
			}
		}
	}

	if (modified) {
		WriteJsonFile(claudeJsonPath, config);
	}
}

// settings.json의 permissions.allow에 와일드카드 권한 등록
static void AddClaudePermission() {
	std::string settingsPath = GetHomePath() + "\\.claude\\settings.json";
	json config = ReadJsonFile(settingsPath);

	if (!config.contains("permissions")) {
		config["permissions"] = json::object();
	}
	auto& perms = config["permissions"];
	if (!perms.contains("allow")) {
		perms["allow"] = json::array();
	}

	auto& allowList = perms["allow"];

	// 이미 등록돼 있는지 확인
	for (const auto& item : allowList) {
		if (item.is_string() && item.get<std::string>() == PERM_WILDCARD) {
			return;  // 이미 있음
		}
	}

	allowList.push_back(PERM_WILDCARD);
	WriteJsonFile(settingsPath, config);
}

// settings.json에서 권한 제거
static void RemoveClaudePermission() {
	std::string settingsPath = GetHomePath() + "\\.claude\\settings.json";
	json config = ReadJsonFile(settingsPath);

	if (!config.contains("permissions")) return;
	auto& perms = config["permissions"];
	if (!perms.contains("allow")) return;

	json cleaned = json::array();
	for (const auto& item : perms["allow"]) {
		if (item.is_string()) {
			std::string s = item.get<std::string>();
			// mcp__veh-debugger__ 로 시작하는 항목 제거
			if (s.find("mcp__veh-debugger__") == 0) continue;
		}
		cleaned.push_back(item);
	}

	perms["allow"] = cleaned;
	WriteJsonFile(settingsPath, config);
}

// --- JSON/TOML 직접 수정 방식 (폴백) ---

static bool IsInstalledJson(const std::string& path) {
	json data = ReadJsonFile(path);
	return data.contains("mcpServers") &&
	       data["mcpServers"].contains(SERVER_NAME);
}

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

static bool UninstallJson(const std::string& path) {
	json data = ReadJsonFile(path);
	if (!data.contains("mcpServers")) return true;
	data["mcpServers"].erase(SERVER_NAME);
	return WriteJsonFile(path, data);
}

// --- TOML ---

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

static bool InstallToml(const std::string& path, const std::string& serverPath) {
	std::string content;
	{
		std::ifstream f(path);
		if (f.is_open()) {
			std::ostringstream ss;
			ss << f.rdbuf();
			content = ss.str();
		}
	}

	std::string section = "[mcp_servers.";
	section += SERVER_NAME;
	section += "]";

	std::string newBlock = section + "\n";
	newBlock += "command = \"" + NormalizePath(serverPath) + "\"\n";
	newBlock += "args = [\"--log=veh-mcp.log\"]\n";
	newBlock += "enabled = true\n";

	auto pos = content.find(section);
	if (pos != std::string::npos) {
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

	while (!content.empty() && (content.back() == '\n' || content.back() == '\r')) {
		content.pop_back();
	}
	content += "\n";

	std::ofstream fout(path);
	if (!fout.is_open()) return false;
	fout << content;
	return fout.good();
}

// --- 공개 API ---

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
	std::string normalizedPath = NormalizePath(serverPath);

	if (agent.name == "claude-code") {
		// Claude Code: claude CLI 우선 시도, 실패 시 settings.json 직접 수정
		std::string claudePath = FindClaudeCLI();
		if (!claudePath.empty()) {
			if (InstallClaudeMCPAdd(claudePath, serverPath)) {
				printf("  %-20s [installed] (claude mcp add)\n", agent.displayName.c_str());
				// 프로젝트별 경로 업데이트
				UpdateClaudeProjectMCPServers(normalizedPath);
				// 권한 등록
				AddClaudePermission();
				printf("  %-20s [permissions] -> %s\n", "", PERM_WILDCARD);
				return true;
			}
			printf("  [Claude Code] claude mcp add failed, falling back to settings.json\n");
		} else {
			printf("  [Claude Code] 'claude' CLI not found, writing settings.json directly\n");
		}

		// 폴백: settings.json 직접 수정
		bool ok = InstallJson(agent.configPath, serverPath);
		if (ok) {
			AddClaudePermission();
			printf("  %-20s [installed] -> %s\n", agent.displayName.c_str(), agent.configPath.c_str());
			printf("  %-20s [permissions] -> %s\n", "", PERM_WILDCARD);
		}
		return ok;
	}

	if (agent.name == "codex") {
		return InstallToml(agent.configPath, serverPath);
	}

	return InstallJson(agent.configPath, serverPath);
}

bool UninstallFromAgent(const AgentConfig& agent) {
	if (agent.name == "claude-code") {
		// Claude CLI로 제거 시도
		std::string claudePath = FindClaudeCLI();
		if (!claudePath.empty()) {
			std::string removeCmd = "\"\"" + claudePath + "\" mcp remove " + SERVER_NAME + "\"";
			FILE* pipe = _popen(removeCmd.c_str(), "r");
			if (pipe) _pclose(pipe);
		}
		// settings.json에서도 제거
		UninstallJson(agent.configPath);
		// 권한 제거
		RemoveClaudePermission();
		return true;
	}

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
