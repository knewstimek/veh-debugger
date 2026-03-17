/* VEH Debugger test target - attach 대상으로 사용 */
#include <windows.h>
#include <stdio.h>

volatile int g_counter = 0;
volatile int g_value = 0x41414141;

int main() {
    printf("VEH Debugger Test Target\n");
    printf("PID: %d\n", GetCurrentProcessId());
    printf("g_counter addr: 0x%p\n", &g_counter);
    printf("g_value addr:   0x%p\n", &g_value);
    printf("\nWaiting for debugger... (press Ctrl+C to exit)\n\n");

    while (1) {
        g_counter++;
        if (g_counter % 1000000 == 0) {
            printf("counter=%d, value=0x%X\n", g_counter, g_value);
        }
        Sleep(1);
    }
    return 0;
}
