// Static import of preload_host: records whether the VEH payload initialized before it.
#include <windows.h>

static int g_payloadFirst = -1;

extern "C" __declspec(dllexport) int PreloadPayloadFirst() {
	return g_payloadFirst;
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
	if (reason == DLL_PROCESS_ATTACH)
		g_payloadFirst = (GetModuleHandleW(L"vcruntime_net.dll") || GetModuleHandleW(L"vcruntime_net32.dll")) ? 1 : 0;
	return TRUE;
}
