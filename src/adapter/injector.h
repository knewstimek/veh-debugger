#pragma once
#include <cstdint>
#include <string>
#include <windows.h>

namespace veh {

enum class InjectionMethod {
	Auto,               // 순서대로 시도: CRT → NtCTE → ThreadHijack → QueueUserAPC
	CreateRemoteThread, // 기본 CreateRemoteThread + LoadLibrary
	NtCreateThreadEx,   // ntdll!NtCreateThreadEx (유저모드 후킹 우회)
	ThreadHijack,       // 기존 스레드 컨텍스트 조작 (새 스레드 생성 안 함)
	QueueUserAPC,       // Alertable wait 상태 스레드에 APC 큐잉
};

// 문자열 → enum 변환
InjectionMethod ParseInjectionMethod(const std::string& str);

class Injector {
public:
	// 지정된 방식으로 DLL 인젝션
	static bool InjectDll(uint32_t pid, const std::string& dllPath,
		InjectionMethod method = InjectionMethod::Auto);

	// 프로세스 생성 + 인젝션
	static uint32_t LaunchAndInject(
		const std::string& exePath,
		const std::string& args,
		const std::string& workingDir,
		const std::string& dllPath,
		bool stopOnEntry,
		InjectionMethod method = InjectionMethod::Auto);

	// DLL 이젝트
	static bool EjectDll(uint32_t pid, const std::string& dllName);

	// WoW64 감지
	static bool IsWow64Process(uint32_t pid);

	// 비트니스에 맞는 DLL 자동 선택
	static std::string SelectDllForTarget(uint32_t pid, const std::string& dllDir);

private:
	static bool EnableDebugPrivilege();

	// 타겟 프로세스에 DLL 경로 문자열 할당
	static LPVOID AllocRemoteString(HANDLE process, const std::string& str);
	static void FreeRemoteString(HANDLE process, LPVOID remoteMem);

	// 개별 인젝션 방식
	static bool InjectViaCreateRemoteThread(HANDLE process, LPVOID remoteStr);
	static bool InjectViaNtCreateThreadEx(HANDLE process, LPVOID remoteStr);
	static bool InjectViaThreadHijack(HANDLE process, uint32_t pid, LPVOID remoteStr);
	static bool InjectViaQueueUserAPC(HANDLE process, uint32_t pid, LPVOID remoteStr);
};

} // namespace veh
