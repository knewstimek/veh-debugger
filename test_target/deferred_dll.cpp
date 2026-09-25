// Late-loaded module for deferred (pending) breakpoint tests; line 3 is the source BP target.
extern "C" __declspec(dllexport) __declspec(noinline) int deferred_func(int value) {
	int result = value * 2 + 1;
	return result;
}
