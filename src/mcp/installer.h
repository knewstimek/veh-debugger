#pragma once
#include <string>
#include <vector>

namespace veh {

struct AgentConfig {
	std::string name;           // "claude-code", "cursor", "windsurf", "codex", "claude-desktop"
	std::string displayName;    // 표시용
	std::string configPath;     // 설정 파일 절대 경로
	bool exists;                // 설정 파일 존재 여부
	bool installed;             // 이미 등록 여부
};

// 지원하는 에이전트 목록과 설정 파일 경로를 탐지
std::vector<AgentConfig> DetectAgents();

// 특정 에이전트에 MCP 서버 등록
// serverPath: veh-mcp-server.exe 절대 경로
bool InstallToAgent(const AgentConfig& agent, const std::string& serverPath);

// 특정 에이전트에서 MCP 서버 제거
bool UninstallFromAgent(const AgentConfig& agent);

// 자기 자신의 절대 경로 반환
std::string GetSelfPath();

} // namespace veh
