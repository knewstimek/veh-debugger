// VEH Debugger 테스트 타겟
// Sleep에 브레이크포인트를 걸어서 테스트
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <intrin.h>

volatile int g_counter = 0;
volatile int g_trace_memory = 0;
void* volatile g_trace_executable = nullptr;

__declspec(noinline) int TraceCoverageTarget(volatile int value) {
	int result = value;
	for (int i = 0; i < 4; ++i) {
		if ((result + i) & 1)
			result += i + 3;
		else
			result ^= i + 7;
		g_trace_memory = result;
	}
	return result;
}

__declspec(noinline) DWORD TraceFunctionScopeTarget(volatile int value) {
	// The imported API deliberately leaves the function's decoded range.  A
	// function-scoped trace must filter that execution and resume at this call's
	// return address before stopping at this function's own return.
	return GetCurrentThreadId() ^ static_cast<DWORD>(value);
}

__declspec(noinline) int TraceIndirectTargetA(int value) { return value + 11; }
__declspec(noinline) int TraceIndirectTargetB(int value) { return value ^ 0x35; }

__declspec(noinline) int TraceIndirectCoverageTarget(volatile int value) {
	int (__cdecl * volatile target)(int) = (value & 1) ? TraceIndirectTargetA : TraceIndirectTargetB;
	return target(value);
}

__declspec(noinline) void TraceExecutableWriteTarget() {
	auto* code = static_cast<volatile unsigned char*>(g_trace_executable);
	*code = 0xC3; // ret, valid in both x86 and x64 mode
	reinterpret_cast<void(*)()>(g_trace_executable)();
}

__declspec(noinline) int TraceExceptionCoverageTarget() {
	volatile int result = 0;
	__ud2();
	result = 7;
	return result;
}

LONG CALLBACK TraceCoverageExceptionHandler(PEXCEPTION_POINTERS info) {
	if (!info || info->ExceptionRecord->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION)
		return EXCEPTION_CONTINUE_SEARCH;
#ifdef _WIN64
	info->ContextRecord->Rip += 2;
#else
	info->ContextRecord->Eip += 2;
#endif
	return EXCEPTION_CONTINUE_EXECUTION;
}

void WorkFunction() {
	int localCounter = g_counter;
	double pi = 3.14159265;
	const char* msg = "hello";
	g_counter++;
	localCounter = g_counter;
	printf("[%d] Working... pi=%.2f msg=%s\n", localCounter, pi, msg);
}

// Overlapping instructions (valid x86 and x64): a linear sweep decodes +2 as
// "mov eax, imm32" (B8 31 C0 90 90), but execution jumps from +0 to +3 and runs
// xor eax,eax / nop / nop / ret, so +3/+5/+6 are executed off the sweep.
static const unsigned char kTraceOverlapCode[] = {0xEB, 0x01, 0xB8, 0x31, 0xC0, 0x90, 0x90, 0xC3};

__declspec(noinline) int TraceOverlapTarget() {
	auto* code = static_cast<unsigned char*>(g_trace_executable) + 0x100;
	return reinterpret_cast<int (*)()>(code)();
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
	g_trace_executable = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (!g_trace_executable) return 2;
	*static_cast<unsigned char*>(g_trace_executable) = 0xC3;
	memcpy(static_cast<unsigned char*>(g_trace_executable) + 0x100, kTraceOverlapCode, sizeof(kTraceOverlapCode));
	bool traceExceptionMode = argc > 1 && strcmp(argv[1], "--trace-exception") == 0;
	if (traceExceptionMode)
		AddVectoredExceptionHandler(0, TraceCoverageExceptionHandler);

	while (true) {
		if (traceExceptionMode)
			g_counter += TraceExceptionCoverageTarget();
		else
			g_counter = TraceCoverageTarget(g_counter);
		g_counter ^= static_cast<int>(TraceFunctionScopeTarget(g_counter));
		g_counter = TraceIndirectCoverageTarget(g_counter);
		TraceExecutableWriteTarget();
		WorkFunction();
		TraceOverlapTarget();
		SleepEx(1000, TRUE);  // alertable wait — APC 인젝션 테스트 가능
	}

	return 0;
}
