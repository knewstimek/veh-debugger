// VEH Debugger 테스트 타겟
// Sleep에 브레이크포인트를 걸어서 테스트
#include <windows.h>
#include <cstdio>
#include <cstring>

volatile int g_counter = 0;

void WorkFunction() {
	int localCounter = g_counter;
	double pi = 3.14159265;
	const char* msg = "hello";
	g_counter++;
	localCounter = g_counter;
	printf("[%d] Working... pi=%.2f msg=%s\n", localCounter, pi, msg);
}

int main(int argc, char* argv[]) {
	printf("=== VEH Debugger Test Target ===\n");
	printf("PID: %u\n", GetCurrentProcessId());
	printf("Sleep address: 0x%p\n", (void*)&Sleep);

	// --crash: 2초 후 ACCESS_VIOLATION 발생 (exception 테스트용)
	if (argc > 1 && strcmp(argv[1], "--crash") == 0) {
		printf("Crash mode: will trigger ACCESS_VIOLATION in 2 seconds...\n");
		Sleep(2000);
		volatile int* p = nullptr;
		*p = 42;  // ACCESS_VIOLATION
		return 1; // unreachable
	}

	printf("Press Ctrl+C to exit.\n\n");

	while (true) {
		WorkFunction();
		SleepEx(1000, TRUE);  // alertable wait — APC 인젝션 테스트 가능
	}

	return 0;
}
