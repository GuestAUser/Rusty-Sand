/*
 * Source-known QA target. Build with -municode -Wall -Wextra -Werror.
 * Usage: windows_surface.exe [--wait|--args] NEW_MARKER_PATH [arguments...]
 * Only the supplied, previously absent marker is written. --args writes a
 * JSON array using UTF-16 escapes, preserving Unicode and empty arguments.
 * --wait blocks on an unnamed, unsignaled OS event after closing the marker.
 * Its stdout token RUSTY_SAND_FIXTURE_WAIT_V1 announces that the marker is
 * closed and the wait event exists, for event-driven direct fixture checks.
 * Exit 10 means CreateFileW was denied; 11 means WriteFile was denied.
 * Other failures are 20; invalid usage is 2. No network or registry activity.
 *
 * --cleanup is a harness-only recovery path, never run through the sandbox.
 * It terminates processes whose full image path equals this executable's path.
 * The harness must compile into a unique private directory, never a shared
 * executable location. Open process handles pin identity during termination.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static int cleanup(void)
{
    wchar_t own[32768];
    DWORD length = GetModuleFileNameW(NULL, own, 32768);
    if (length == 0 || length >= 32768) {
        return 20;
    }

    const wchar_t *name = wcsrchr(own, L'\\');
    name = name == NULL ? own : name + 1;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 20;
    }

    PROCESSENTRY32W entry;
    memset(&entry, 0, sizeof(entry));
    entry.dwSize = sizeof(entry);
    unsigned int killed = 0;
    int result = 0;
    BOOL found = Process32FirstW(snapshot, &entry);

    while (found) {
        if (entry.th32ProcessID != GetCurrentProcessId()
            && _wcsicmp(entry.szExeFile, name) == 0) {
            HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION
                | PROCESS_TERMINATE | SYNCHRONIZE, FALSE, entry.th32ProcessID);

            if (process == NULL) {
                if (GetLastError() != ERROR_INVALID_PARAMETER) {
                    result = 20;
                }
            } else {
                wchar_t image[32768];
                DWORD capacity = 32768;
                if (!QueryFullProcessImageNameW(process, 0, image, &capacity)) {
                    result = 20;
                } else if (_wcsicmp(image, own) == 0) {
                    if (WaitForSingleObject(process, 0) != WAIT_OBJECT_0) {
                        if (!TerminateProcess(process, 20)
                            || WaitForSingleObject(process, 5000) != WAIT_OBJECT_0) {
                            result = 20;
                        } else {
                            killed++;
                        }
                    }
                }
                if (!CloseHandle(process)) {
                    result = 20;
                }
            }
        }
        found = Process32NextW(snapshot, &entry);
    }

    if (GetLastError() != ERROR_NO_MORE_FILES) {
        result = 20;
    }
    if (!CloseHandle(snapshot)) {
        result = 20;
    }
    printf("{\"killed\":%u,\"status\":%d}\n", killed, result);
    return result;
}

static char *arguments_json(int count, wchar_t **arguments, DWORD *size)
{
    /* Windows command lines are bounded to 32767 UTF-16 code units. Six
     * ASCII bytes per unit plus array punctuation fit in this allocation. */
    size_t capacity = 2;
    for (int index = 0; index < count; index++) {
        capacity += 3 + 6 * wcslen(arguments[index]);
    }

    char *buffer = malloc(capacity + 1);
    if (buffer == NULL) {
        return NULL;
    }

    char *cursor = buffer;
    *cursor++ = '[';
    for (int index = 0; index < count; index++) {
        if (index != 0) {
            *cursor++ = ',';
        }
        *cursor++ = '"';
        for (const wchar_t *unit = arguments[index]; *unit != 0; unit++) {
            int written = snprintf(cursor, 7, "\\u%04x", (unsigned int)*unit);
            if (written != 6) {
                free(buffer);
                return NULL;
            }
            cursor += written;
        }
        *cursor++ = '"';
    }
    *cursor++ = ']';
    *cursor = '\0';
    *size = (DWORD)(cursor - buffer);
    return buffer;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc == 2 && wcscmp(argv[1], L"--cleanup") == 0) {
        return cleanup();
    }

    BOOL wait_mode = argc > 1 && wcscmp(argv[1], L"--wait") == 0;
    BOOL args_mode = argc > 1 && wcscmp(argv[1], L"--args") == 0;
    int path_index = wait_mode || args_mode ? 2 : 1;
    if (argc <= path_index || (!args_mode && argc != path_index + 1)) {
        return 2;
    }

    const char marker[] = "rusty-sand-qa-marker-v1\n";
    DWORD size = (DWORD)(sizeof(marker) - 1);
    char *arguments = args_mode
        ? arguments_json(argc - path_index - 1, argv + path_index + 1, &size)
        : NULL;
    if (args_mode && arguments == NULL) {
        return 20;
    }

    HANDLE file = CreateFileW(argv[path_index], GENERIC_WRITE, 0, NULL,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        free(arguments);
        return error == ERROR_ACCESS_DENIED ? 10 : 20;
    }

    DWORD written = 0;
    BOOL success = WriteFile(file, args_mode ? arguments : marker, size, &written, NULL);
    DWORD error = success ? ERROR_SUCCESS : GetLastError();
    BOOL closed = CloseHandle(file);
    free(arguments);

    if (!closed || (success && written != size)) {
        return 20;
    }
    if (!success) {
        return error == ERROR_ACCESS_DENIED ? 11 : 20;
    }

    if (wait_mode) {
        HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (event == NULL) {
            return 20;
        }
        BOOL announced = puts("RUSTY_SAND_FIXTURE_WAIT_V1") != EOF
            && fflush(stdout) == 0;
        DWORD state = announced ? WaitForSingleObject(event, INFINITE) : WAIT_FAILED;
        BOOL event_closed = CloseHandle(event);
        return state == WAIT_OBJECT_0 && event_closed ? 0 : 20;
    }

    return 0;
}
