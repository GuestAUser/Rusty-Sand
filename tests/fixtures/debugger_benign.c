#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

#define HANDLED_EXCEPTION ((DWORD)0xE0421001u)
#define UNHANDLED_EXCEPTION ((DWORD)0xE0421002u)

static LONG handled_count = 0;

static LONG CALLBACK handle_exception(EXCEPTION_POINTERS *information)
{
    DWORD code = information->ExceptionRecord->ExceptionCode;

    if (code == HANDLED_EXCEPTION) {
        InterlockedIncrement(&handled_count);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code == EXCEPTION_BREAKPOINT
        && information->ExceptionRecord->NumberParameters == 0) {
        /*
         * Our synthetic RaiseException has no INT3 instruction to skip.
         * Direct delivery preserves its continuation address; debugger-first
         * delivery can rewind RIP by one before reaching this VEH. Normalize
         * only that observed case to the exception record's original address.
         * Do not advance an already-correct context or handle other contexts.
         */
        DWORD64 continuation =
            (DWORD64)(ULONG_PTR)information->ExceptionRecord->ExceptionAddress;
        DWORD64 rip = information->ContextRecord->Rip;

        if (rip != continuation) {
            if (rip >= continuation || continuation - rip != 1) {
                return EXCEPTION_CONTINUE_SEARCH;
            }

            information->ContextRecord->Rip = continuation;
        }

        InterlockedIncrement(&handled_count);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static DWORD WINAPI benign_thread(void *argument)
{
    (void)argument;
    return 9;
}

static int emit_events(void)
{
    HMODULE module = LoadLibraryExW(
        L"version.dll",
        NULL,
        LOAD_LIBRARY_SEARCH_SYSTEM32
    );

    if (module == NULL) {
        return 80;
    }

    if (!FreeLibrary(module)) {
        return 81;
    }

    HANDLE thread = CreateThread(NULL, 0, benign_thread, NULL, 0, NULL);
    if (thread == NULL) {
        return 82;
    }

    DWORD wait_result = WaitForSingleObject(thread, INFINITE);
    DWORD thread_code = 0;
    BOOL queried = GetExitCodeThread(thread, &thread_code);
    BOOL closed = CloseHandle(thread);

    if (wait_result != WAIT_OBJECT_0 || !queried || !closed || thread_code != 9) {
        return 83;
    }

    OutputDebugStringA("debugger-ascii");
    OutputDebugStringW(L"debugger-wide-\x03a9");

    void *handler = AddVectoredExceptionHandler(1, handle_exception);
    if (handler == NULL) {
        return 84;
    }

    ULONG_PTR parameters[] = {0x1122, 0x3344, 0x5566};
    RaiseException(HANDLED_EXCEPTION, 0, 3, parameters);
    RaiseException(EXCEPTION_BREAKPOINT, 0, 0, NULL);

    if (RemoveVectoredExceptionHandler(handler) == 0) {
        return 85;
    }

    if (handled_count != 2) {
        return 86;
    }

    OutputDebugStringA("handled-breakpoint");
    return 0;
}

static int wait_for_debugger(int argc, wchar_t **argv)
{
    if (argc != 5) {
        return 90;
    }

    HANDLE ready = OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[2]);
    HANDLE gate = OpenEventW(SYNCHRONIZE, FALSE, argv[3]);

    if (ready == NULL || gate == NULL) {
        if (ready != NULL) {
            CloseHandle(ready);
        }
        if (gate != NULL) {
            CloseHandle(gate);
        }
        return 91;
    }

    FILE *pid_file = NULL;
    errno_t open_result = _wfopen_s(&pid_file, argv[4], L"w");

    if (open_result != 0) {
        CloseHandle(ready);
        CloseHandle(gate);
        return 92;
    }

    int written = fprintf(pid_file, "%lu\n", (unsigned long)GetCurrentProcessId());
    int file_closed = fclose(pid_file);

    if (written < 0 || file_closed != 0 || !SetEvent(ready)) {
        CloseHandle(ready);
        CloseHandle(gate);
        return 93;
    }

    if (!CloseHandle(ready)) {
        CloseHandle(gate);
        return 94;
    }

    /*
     * Tests create the gate before launch. The fixture blocks on a real kernel
     * event; cancellation and timeout tests terminate this owned process.
     */
    DWORD result = WaitForSingleObject(gate, INFINITE);
    BOOL closed = CloseHandle(gate);
    return result == WAIT_OBJECT_0 && closed ? 7 : 95;
}

int wmain(int argc, wchar_t **argv)
{
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);

    if (argc < 2) {
        return 96;
    }

    if (wcscmp(argv[1], L"wait") == 0) {
        return wait_for_debugger(argc, argv);
    }

    int result = emit_events();
    if (result != 0) {
        return result;
    }

    if (wcscmp(argv[1], L"unhandled") == 0) {
        RaiseException(UNHANDLED_EXCEPTION, EXCEPTION_NONCONTINUABLE, 0, NULL);
        return 97;
    }

    if (wcscmp(argv[1], L"flood") == 0) {
        static wchar_t large_string[8193];

        for (unsigned int index = 0; index < 8192; ++index) {
            large_string[index] = L'X';
        }
        large_string[8192] = L'\0';
        OutputDebugStringW(large_string);

        for (unsigned int index = 0; index < 4096; ++index) {
            OutputDebugStringA("flood");
        }

        return 7;
    }

    return wcscmp(argv[1], L"normal") == 0 ? 7 : 98;
}
