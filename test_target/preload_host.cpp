// importTable fixture: writes "first=<0|1> restored=<0|1>" to argv[1], then waits to be terminated.
#include <windows.h>
#include <cstdio>

extern "C" __declspec(dllimport) int PreloadPayloadFirst();

int main(int argc, char** argv) {
	if (argc < 2) return 2;
	auto* base = reinterpret_cast<BYTE*>(GetModuleHandleW(nullptr));
	auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + reinterpret_cast<IMAGE_DOS_HEADER*>(base)->e_lfanew);
	const bool restored = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress <
		nt->OptionalHeader.SizeOfImage;
	char temp[MAX_PATH + 8];
	snprintf(temp, sizeof(temp), "%s.tmp", argv[1]);
	FILE* out = fopen(temp, "w");
	if (!out) return 3;
	fprintf(out, "first=%d restored=%d\n", PreloadPayloadFirst(), restored ? 1 : 0);
	fclose(out);
	if (!MoveFileExA(temp, argv[1], MOVEFILE_REPLACE_EXISTING)) return 4;
	Sleep(30000);
	return 0;
}
