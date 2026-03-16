// VEH Debugger 테스트 타겟
// Sleep에 브레이크포인트를 걸어서 테스트
#include <windows.h>
#include <cstdio>

volatile int g_counter = 0;

void WorkFunction() {
	g_counter++;
	printf("[%d] Working...\n", g_counter);
}

int main() {
	printf("=== VEH Debugger Test Target ===\n");
	printf("PID: %u\n", GetCurrentProcessId());
	printf("Sleep address: 0x%p\n", (void*)&Sleep);
	printf("Press Ctrl+C to exit.\n\n");

	while (true) {
		WorkFunction();
		SleepEx(1000, TRUE);  // alertable wait — APC 인젝션 테스트 가능
	}

	return 0;
}
