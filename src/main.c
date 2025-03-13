#include "winmem.h"

BOOL EnumModulesProc(pModuleInfo info, void *userData) {
    if (info == NULL) { return FALSE; }
    if (strcmp("test.exe", info->name) == 0) {
        BYTE **baseAddress = (BYTE**)userData;
        *(baseAddress) = info->baseAddress + 0x7098;
        printf("addr: %p\n", baseAddress);
    }
    printf_s(
        "\n"
        "     MODULE INFO       \n"
        "   Name:         %s    \n"
        "   PID:          %d    \n"
        "   Handle:       %p    \n"
        "   Base address: %p    \n"
        "\n",
        info->name,
        info->processID,
        info->hModule,
        info->baseAddress
    );
    return TRUE;
}

int main() {
    printf_s("Hello, %s!\n\n", __FILE__);

    // ----------------------------------
    ModuleInfo mInfo = {0};
    DWORD pid = GetPIDByName("test.exe");
    GetModuleInfo("test.exe", pid, &mInfo);
    // ----------------------------------
    HANDLE hProcess = AttachByPID(pid, PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE);
    // ----------------------------------
    BYTE *baseAddress = mInfo.baseAddress;
    UINT64 numAddress = 0;
    ReadMemory(hProcess, (LPCVOID)(baseAddress + 0x7098), &numAddress, sizeof(UINT64), NULL);
    // ----------------------------------
    int num = 0;
    numAddress += 0x36C;
    ReadMemory(hProcess, (LPCVOID)numAddress, (LPVOID)&num, sizeof(int), NULL);
    printf_s("Value: %d\n", num);
    // ----------------------------------
    int data = 10;
    WriteMemory(hProcess, (LPVOID)numAddress, (LPVOID)&data, sizeof(data), NULL);
    ReadMemory(hProcess, (LPCVOID)numAddress, (LPVOID)&num, sizeof(num), NULL);
    printf_s("Value: %d\n", num);
    // ----------------------------------

    Deattach(hProcess);
    return EXIT_SUCCESS;
}