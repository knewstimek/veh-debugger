// Starts without deferred_dll.dll and loads it later, so breakpoints set on its symbols
// or source lines stay pending until the ModuleLoaded event binds them.
#include <windows.h>
#include <cstdio>

int main() {
	Sleep(1000);
	HMODULE module = LoadLibraryA("deferred_dll.dll");
	if (!module) {
		printf("host: LoadLibrary failed (%lu)\n", GetLastError());
		return 1;
	}
	printf("host: module loaded at %p\n", static_cast<void*>(module));

	auto deferredFunc = reinterpret_cast<int (*)(int)>(GetProcAddress(module, "deferred_func"));
	if (!deferredFunc) {
		printf("host: GetProcAddress failed\n");
		return 1;
	}
	// Keep calling: the breakpoint binds asynchronously after the module load.
	for (int i = 0; i < 60; ++i) {
		printf("host: deferred_func(%d) = %d\n", i, deferredFunc(i));
		fflush(stdout);
		Sleep(500);
	}
	FreeLibrary(module);
	return 0;
}
