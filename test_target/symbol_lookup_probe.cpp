// Synthetic DLL exports used by duplicate-name and unload/reload regression tests.
#ifdef SYMBOL_PROBE_RELOAD
extern "C" __declspec(dllexport) __declspec(noinline) int ReloadOnlyProbe(int value) {
    return value + 57;
}
#else
// Two independently loaded synthetic DLLs deliberately export the same name.
extern "C" __declspec(dllexport) __declspec(noinline) int SharedProbe(int value) {
#ifdef SYMBOL_PROBE_A
    return value + 11;
#else
    return value + 23;
#endif
}
#ifdef SYMBOL_PROBE_A
extern "C" __declspec(dllexport) __declspec(noinline) int UniqueProbe(int value) {
    return value + 37;
}
#endif


#endif
