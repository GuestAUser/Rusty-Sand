#include <windows.h>
#include <stdio.h>

/* Run with a WSL Popen stdin pipe whose writer remains open and empty. This
 * exercises the actual interop handle, not a Windows-created stand-in pipe. */
int main(void)
{
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD original = 0;
    DWORD nonblocking = PIPE_NOWAIT;
    DWORD count = 0;
    DWORD restored = 0;
    char byte = 0;

    if (!GetNamedPipeHandleStateW(input, &original, NULL, NULL, NULL, NULL, 0)) {
        fprintf(stderr, "query mode error=%lu\n", GetLastError());
        return 1;
    }
    if (!SetNamedPipeHandleState(input, &nonblocking, NULL, NULL)) {
        fprintf(stderr, "set mode error=%lu\n", GetLastError());
        return 2;
    }

    BOOL result = ReadFile(input, &byte, 1, &count, NULL);
    DWORD error = GetLastError();

    if (!SetNamedPipeHandleState(input, &original, NULL, NULL)) {
        fprintf(stderr, "restore mode error=%lu\n", GetLastError());
        return 3;
    }
    if (!GetNamedPipeHandleStateW(input, &restored, NULL, NULL, NULL, NULL, 0)) {
        return 4;
    }
    printf("type=%lu original=%lu read=%d bytes=%lu error=%lu restored=%lu\n",
           GetFileType(input), original, result, count, error, restored);

    return (!result && error == ERROR_NO_DATA && count == 0 && original == restored) ? 0 : 5;
}
