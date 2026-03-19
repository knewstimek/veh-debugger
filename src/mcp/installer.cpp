#include "installer.h"
#include <nlohmann/json.hpp>

#define TOML_EXCEPTIONS 0
#include <tomlplusplus/toml.hpp>

#include <windows.h>
#include <shlobj.h>
#include <fstream>
#include <sstream>
#include <filesystem>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace veh {

static const char* SERVER_NAME = "veh-debugger";
static const char* PERM_WILDCARD = "mcp__veh-debugger__*";

// --- Unicode 유틸리티 ---

// UTF-8 → wstring
static std::wstring Utf8ToWide(const std::string& str) {
	if (str.empty()) return {};
	int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), nullptr, 0);
	if (len <= 0) return {};
	std::wstring result(len, L'\0');
	MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), result.data(), len);
	return result;
}

// wstring → UTF-8
static std::string WideToUtf8(const std::wstring& wstr) {
	if (wstr.empty()) return {};
	int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
	if (len <= 0) return {};
	std::string result(len, '\0');
	WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), result.data(), len, nullptr, nullptr);
	return result;
}

// %USERPROFILE% 경로 반환 (Unicode)
static std::string GetHomePath() {
	wchar_t path[MAX_PATH];
	if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, path))) {
		return WideToUtf8(path);
	}
	// 폴백: 환경변수
	wchar_t buf[MAX_PATH];
	DWORD len = GetEnvironmentVariableW(L"USERPROFILE", buf, MAX_PATH);
	if (len > 0 && len < MAX_PATH) return WideToUtf8(std::wstring(buf, len));
	return "C:\\Users\\Default";
}

// %APPDATA% 경로 반환 (Unicode)
static std::string GetAppDataPath() {
	wchar_t path[MAX_PATH];
	if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, path))) {
		return WideToUtf8(path);
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

// --- JSON 파일 I/O (atomic write) ---

static json ReadJsonFile(const std::string& path) {
	std::ifstream f(Utf8ToWide(path));
	if (!f.is_open()) return json::object();
	try {
		return json::parse(f);
	} catch (...) {
		return json::object();
	}
}

// atomic write: 임시 파일에 쓰고 rename
static bool WriteJsonFile(const std::string& path, const json& data) {
	fs::path p(Utf8ToWide(path));
	if (p.has_parent_path()) {
		std::error_code ec;
		fs::create_directories(p.parent_path(), ec);
	}

	std::string tmpPath = path + ".tmp";
	{
		std::ofstream f(Utf8ToWide(tmpPath));
		if (!f.is_open()) return false;
		f << data.dump(2) << std::endl;
		if (!f.good()) return false;
	}

	std::error_code ec;
	fs::rename(fs::path(Utf8ToWide(tmpPath)), p, ec);
	if (ec) {
		// rename 실패 시 (크로스 볼륨 등) copy + delete 폴백
		std::error_code copyEc;
		fs::copy_file(fs::path(Utf8ToWide(tmpPath)), p,
		              fs::copy_options::overwrite_existing, copyEc);
		fs::remove(fs::path(Utf8ToWide(tmpPath)));  // 정리 (실패 무시)
		return !copyEc;
	}
	return true;
}

// --- Claude CLI 방식 ---

// CreateProcess로 명령 실행 (셸 우회 — 명령 인젝션 방지, Unicode 지원)
static bool RunProcess(const std::string& exe, const std::string& args, DWORD timeoutMs = 30000) {
	std::wstring cmdLine = L"\"" + Utf8ToWide(exe) + L"\" " + Utf8ToWide(args);

	STARTUPINFOW si = {};
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	PROCESS_INFORMATION pi = {};

	// .cmd/.bat 파일은 cmd.exe를 거쳐야 함
	std::string exeLower = exe;
	for (char& c : exeLower) c = (char)tolower((unsigned char)c);
	bool isBatch = (exeLower.size() >= 4 &&
	                (exeLower.substr(exeLower.size() - 4) == ".cmd" ||
	                 exeLower.substr(exeLower.size() - 4) == ".bat"));

	BOOL ok;
	if (isBatch) {
		// lpApplicationName에 cmd.exe 전체 경로 지정 (셸 메타문자 인젝션 방지)
		wchar_t sysDir[MAX_PATH];
		GetSystemDirectoryW(sysDir, MAX_PATH);
		std::wstring cmdExe = std::wstring(sysDir) + L"\\cmd.exe";
		std::wstring batchCmd = L"\"" + cmdExe + L"\" /c " + cmdLine;
		ok = CreateProcessW(cmdExe.c_str(), batchCmd.data(), NULL, NULL, FALSE,
		                    CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
	} else {
		std::wstring wExe = Utf8ToWide(exe);
		ok = CreateProcessW(wExe.c_str(), cmdLine.data(), NULL, NULL, FALSE,
		                    CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
	}

	if (!ok) return false;

	DWORD waitResult = WaitForSingleObject(pi.hProcess, timeoutMs);
	if (waitResult == WAIT_TIMEOUT) {
		TerminateProcess(pi.hProcess, 1);
		WaitForSingleObject(pi.hProcess, 5000);
	}
	DWORD exitCode = 1;
	GetExitCodeProcess(pi.hProcess, &exitCode);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return exitCode == 0;
}

// PATH에서 claude 실행파일 찾기 (Unicode)
static std::string FindClaudeCLI() {
	const wchar_t* names[] = {L"claude.exe", L"claude.cmd", L"claude"};
	wchar_t result[MAX_PATH];

	for (auto name : names) {
		DWORD len = SearchPathW(NULL, name, NULL, MAX_PATH, result, NULL);
		if (len > 0 && len < MAX_PATH) {
			return WideToUtf8(std::wstring(result, len));
		}
	}
	return "";
}

// claude mcp add --scope user 로 등록
static bool InstallClaudeMCPAdd(const std::string& claudePath, const std::string& serverPath) {
	std::string normalizedPath = NormalizePath(serverPath);

	// 기존 등록 제거 (업데이트 지원)
	RunProcess(claudePath, "mcp remove " + std::string(SERVER_NAME), 10000);

	// --scope user 로 global 등록
	std::string addArgs = "mcp add --scope user " + std::string(SERVER_NAME) +
	                      " \"" + normalizedPath + "\"";
	if (!RunProcess(claudePath, addArgs)) {
		fprintf(stderr, "  [Claude Code] claude mcp add failed\n");
		return false;
	}

	return true;
}

// ~/.claude.json 의 global + 프로젝트별 mcpServers 경로 업데이트
static void UpdateClaudeJsonMCPServers(const std::string& newPath) {
	std::string claudeJsonPath = GetHomePath() + "\\.claude.json";
	json config = ReadJsonFile(claudeJsonPath);

	bool modified = false;

	// global mcpServers (루트)
	if (config.contains("mcpServers") && config["mcpServers"].is_object() &&
	    config["mcpServers"].contains(SERVER_NAME)) {
		auto& entry = config["mcpServers"][SERVER_NAME];
		if (entry.is_object() && entry.contains("command")) {
			std::string oldCmd = entry["command"].get<std::string>();
			if (oldCmd != newPath) {
				entry["command"] = newPath;
				modified = true;
			}
		}
	}

	// 프로젝트별 mcpServers
	if (config.contains("projects") && config["projects"].is_object()) {
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
	}

	if (modified) {
		WriteJsonFile(claudeJsonPath, config);
	}
}

// ~/.claude.json 에서 veh-debugger MCP 항목 제거 (global + 프로젝트별)
static void RemoveFromClaudeJson() {
	std::string claudeJsonPath = GetHomePath() + "\\.claude.json";
	json config = ReadJsonFile(claudeJsonPath);

	bool modified = false;

	// global mcpServers
	if (config.contains("mcpServers") && config["mcpServers"].is_object() &&
	    config["mcpServers"].contains(SERVER_NAME)) {
		config["mcpServers"].erase(SERVER_NAME);
		modified = true;
	}

	// 프로젝트별 mcpServers
	if (config.contains("projects") && config["projects"].is_object()) {
		for (auto& [projPath, projConfig] : config["projects"].items()) {
			if (!projConfig.is_object()) continue;
			if (!projConfig.contains("mcpServers")) continue;
			auto& servers = projConfig["mcpServers"];
			if (servers.is_object() && servers.contains(SERVER_NAME)) {
				servers.erase(SERVER_NAME);
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
			if (s.find("mcp__veh-debugger__") == 0) continue;
		}
		cleaned.push_back(item);
	}

	perms["allow"] = cleaned;
	WriteJsonFile(settingsPath, config);
}

// --- JSON 설정 ---

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

// --- TOML (toml++ 라이브러리 사용) ---

static toml::table ParseTomlFile(const std::string& path) {
	std::ifstream f(Utf8ToWide(path));
	if (!f.is_open()) return {};
	try {
		return toml::parse(f, path);
	} catch (...) {
		return {};
	}
}

static bool IsInstalledToml(const std::string& path) {
	auto tbl = ParseTomlFile(path);
	if (tbl.empty()) return false;
	if (auto servers = tbl["mcp_servers"].as_table()) {
		return servers->contains(SERVER_NAME);
	}
	return false;
}

static bool WriteTomlFile(const std::string& path, const toml::table& tbl) {
	fs::path p(Utf8ToWide(path));
	if (p.has_parent_path()) {
		std::error_code ec;
		fs::create_directories(p.parent_path(), ec);
	}

	std::string tmpPath = path + ".tmp";
	{
		std::ofstream f(Utf8ToWide(tmpPath));
		if (!f.is_open()) return false;
		f << tbl;
		if (!f.good()) return false;
	}

	std::error_code ec;
	fs::rename(fs::path(Utf8ToWide(tmpPath)), p, ec);
	if (ec) {
		std::error_code copyEc;
		fs::copy_file(fs::path(Utf8ToWide(tmpPath)), p,
		              fs::copy_options::overwrite_existing, copyEc);
		fs::remove(fs::path(Utf8ToWide(tmpPath)));
		return !copyEc;
	}
	return true;
}

static bool InstallToml(const std::string& path, const std::string& serverPath) {
	toml::table tbl = ParseTomlFile(path);

	// mcp_servers 테이블 확보
	if (!tbl.contains("mcp_servers") || !tbl["mcp_servers"].is_table()) {
		tbl.insert_or_assign("mcp_servers", toml::table{});
	}
	auto* servers = tbl["mcp_servers"].as_table();

	// 서버 항목 생성/업데이트
	toml::table entry;
	entry.insert_or_assign("command", NormalizePath(serverPath));
	entry.insert_or_assign("args", toml::array{"--log=veh-mcp.log"});
	entry.insert_or_assign("enabled", true);
	servers->insert_or_assign(SERVER_NAME, std::move(entry));

	return WriteTomlFile(path, tbl);
}

static bool UninstallToml(const std::string& path) {
	auto tbl = ParseTomlFile(path);
	if (tbl.empty()) return true;  // 파일 없거나 파싱 실패 → 이미 없는 것

	if (auto servers = tbl["mcp_servers"].as_table()) {
		servers->erase(SERVER_NAME);
	}

	return WriteTomlFile(path, tbl);
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
		a.exists = fs::exists(fs::path(Utf8ToWide(a.configPath)));
		a.installed = a.exists && IsInstalledJson(a.configPath);
		agents.push_back(a);
	}

	// Claude Desktop
	{
		AgentConfig a;
		a.name = "claude-desktop";
		a.displayName = "Claude Desktop";
		a.configPath = appData + "\\Claude\\claude_desktop_config.json";
		a.exists = fs::exists(fs::path(Utf8ToWide(a.configPath)));
		a.installed = a.exists && IsInstalledJson(a.configPath);
		agents.push_back(a);
	}

	// Cursor
	{
		AgentConfig a;
		a.name = "cursor";
		a.displayName = "Cursor";
		a.configPath = home + "\\.cursor\\mcp.json";
		a.exists = fs::exists(fs::path(Utf8ToWide(a.configPath)));
		a.installed = a.exists && IsInstalledJson(a.configPath);
		agents.push_back(a);
	}

	// Windsurf
	{
		AgentConfig a;
		a.name = "windsurf";
		a.displayName = "Windsurf";
		a.configPath = home + "\\.codeium\\windsurf\\mcp_config.json";
		a.exists = fs::exists(fs::path(Utf8ToWide(a.configPath)));
		a.installed = a.exists && IsInstalledJson(a.configPath);
		agents.push_back(a);
	}

	// Codex CLI (TOML)
	{
		AgentConfig a;
		a.name = "codex";
		a.displayName = "Codex CLI";
		a.configPath = home + "\\.codex\\config.toml";
		a.exists = fs::exists(fs::path(Utf8ToWide(a.configPath)));
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
				fprintf(stderr, "  %-20s [installed] (claude mcp add)\n", agent.displayName.c_str());
				UpdateClaudeJsonMCPServers(normalizedPath);
				AddClaudePermission();
				fprintf(stderr, "  %-20s [permissions] -> %s\n", "", PERM_WILDCARD);
				return true;
			}
			fprintf(stderr, "  [Claude Code] claude mcp add failed, falling back to settings.json\n");
		} else {
			fprintf(stderr, "  [Claude Code] 'claude' CLI not found, writing settings.json directly\n");
		}

		// 폴백: settings.json 직접 수정
		bool ok = InstallJson(agent.configPath, serverPath);
		if (ok) {
			UpdateClaudeJsonMCPServers(normalizedPath);
			AddClaudePermission();
			fprintf(stderr, "  %-20s [installed] -> %s\n", agent.displayName.c_str(), agent.configPath.c_str());
			fprintf(stderr, "  %-20s [permissions] -> %s\n", "", PERM_WILDCARD);
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
		std::string claudePath = FindClaudeCLI();
		if (!claudePath.empty()) {
			RunProcess(claudePath, "mcp remove " + std::string(SERVER_NAME), 10000);
		}
		UninstallJson(agent.configPath);
		RemoveFromClaudeJson();
		RemoveClaudePermission();
		return true;
	}

	if (agent.name == "codex") {
		return UninstallToml(agent.configPath);
	}

	return UninstallJson(agent.configPath);
}

std::string GetSelfPath() {
	// 동적 버퍼로 long path 지원
	std::wstring buf(MAX_PATH, L'\0');
	DWORD len = GetModuleFileNameW(NULL, buf.data(), (DWORD)buf.size());
	while (len == buf.size() && buf.size() < 65536) {
		buf.resize(buf.size() * 2);
		len = GetModuleFileNameW(NULL, buf.data(), (DWORD)buf.size());
	}
	if (len == 0) return "";
	buf.resize(len);
	return WideToUtf8(buf);
}

} // namespace veh
