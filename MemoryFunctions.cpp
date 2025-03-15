#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

#include "MemoryFunctions.h"
#include "config.h"

HANDLE hProcess = nullptr;
DWORD processId = -1;
INT moduleBase = 0x0;

DWORD GetProcId(const wchar_t* procName)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);

        if (Process32First(hSnap, &procEntry))
        {
            while (Process32Next(hSnap, &procEntry))
            {

                if (!_wcsicmp(procEntry.szExeFile, procName))
                {
                    procId = procEntry.th32ProcessID;
                    break;
                }
            }
        }
    }
    CloseHandle(hSnap);
    return procId;
}

bool AttachToProcess(const wchar_t* procName)
{
    processId = GetProcId(procName);
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    moduleBase = GetModuleBaseAddress(procName);
    std::cout
        << "Attached to process: " << std::dec << processId << std::endl;
    return hProcess != nullptr;
}

uintptr_t GetModuleBaseAddress(const wchar_t* modName)
{
    uintptr_t modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        std::cout << "---------------------MODULES\n";
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry))
        {
            while (Module32Next(hSnap, &modEntry))
            {
                std::wcout << "  >  " << modEntry.szModule << "\n        Address: 0x" << std::hex << std::uppercase << (UINT)modEntry.modBaseAddr
                    << " Size: 0x" << std::hex << modEntry.modBaseSize << std::endl;
                if (!_wcsicmp(modEntry.szModule, modName))
                {
                    modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                    moduleBase = (INT)modBaseAddr;
                    break;
                }
            }
        }
        std::cout << "----------------------------\n";
    }
    CloseHandle(hSnap);
    return modBaseAddr;
}

BOOLEAN FindArrayOfBytes(PFOUND_ADDRESSES FoundAddresses, BYTE* DataToFind, INT DataSize, BOOL SkipCompleteMatches)
{
    if ((NULL == FoundAddresses) || (NULL == DataToFind) || (NULL == DataSize))
    {
        return FALSE;
    }

    DWORD dwReadableMask = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY
        | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
    DWORD dwProtectedMask = (PAGE_GUARD | PAGE_NOACCESS);

    INT iFoundSize = 10;
    UINT_PTR ulCurrAddr = NULL;
    BYTE* lpBuff = NULL;
    SIZE_T ulBytesRead = NULL;
    SYSTEM_INFO SysInfo;
    MEMORY_BASIC_INFORMATION Mbi;

    ZeroMemory(&SysInfo, sizeof(SysInfo));
    ZeroMemory(&Mbi, sizeof(Mbi));

    FoundAddresses->Addresses = (UINT_PTR*)malloc(iFoundSize * sizeof(UINT_PTR));
    GetSystemInfo(&SysInfo);
    ulCurrAddr = (UINT_PTR)(SysInfo.lpMinimumApplicationAddress);

    while (sizeof(Mbi) == VirtualQueryEx(hProcess, (LPVOID)(ulCurrAddr), &Mbi, sizeof(Mbi)),
        (ulCurrAddr <= (UINT_PTR)(SysInfo.lpMaximumApplicationAddress)))
    {
        //printf("Address: 0x%x\n", (UINT_PTR)(ulCurrAddr));
        if ((dwReadableMask & Mbi.Protect) && (FALSE == (dwProtectedMask & Mbi.Protect)))
        {
            lpBuff = (BYTE*)(malloc(Mbi.RegionSize));
            if (ReadProcessMemory(hProcess, (LPVOID)(ulCurrAddr), lpBuff, Mbi.RegionSize, &ulBytesRead) == TRUE)
            {
                if (ulBytesRead == Mbi.RegionSize)
                {
                    for (UINT i = 0; i < Mbi.RegionSize; ++i)
                    {
                        if (memcmp((LPCVOID)(lpBuff + i), DataToFind, DataSize) == 0)
                        {
                            //printf("Offset: %x\n", (UINT_PTR)(ulCurrAddr + i));
                            if (iFoundSize == (FoundAddresses->NumberOfAddresses + 1))
                            {
                                LPVOID lpTemp = realloc(FoundAddresses->Addresses, (iFoundSize + 50) * sizeof(UINT_PTR));
                                if (lpTemp == NULL)
                                {
                                    free(FoundAddresses->Addresses);
                                    free(lpBuff);
                                    return FALSE;
                                }
                                FoundAddresses->Addresses = (UINT_PTR*)(lpTemp);
                            }
                            FoundAddresses->Addresses[FoundAddresses->NumberOfAddresses] = (ulCurrAddr + i);
                            FoundAddresses->NumberOfAddresses++;
                            if (TRUE == SkipCompleteMatches) {
                                i += DataSize;
                            }
                        }
                    }
                }
            }
            free(lpBuff);
        }
        ulCurrAddr = (UINT_PTR)(Mbi.BaseAddress) + Mbi.RegionSize;
    }
    if (FoundAddresses->NumberOfAddresses == 0)
    {
        return FALSE;
    }
    return TRUE;
}

uintptr_t FindArrayOfBytesOne(BYTE* DataToFind, SIZE_T DataSize)
{
    if ((NULL == DataToFind) || (NULL == DataSize))
    {
        return 1;
    }

    DWORD dwReadableMask = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY
        | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
    DWORD dwProtectedMask = (PAGE_GUARD | PAGE_NOACCESS);

    INT iFoundSize = 10;
    UINT_PTR ulCurrAddr = NULL;
    BYTE* lpBuff = NULL;
    SIZE_T ulBytesRead = NULL;
    SYSTEM_INFO SysInfo;
    MEMORY_BASIC_INFORMATION Mbi;

    ZeroMemory(&SysInfo, sizeof(SysInfo));
    ZeroMemory(&Mbi, sizeof(Mbi));

    GetSystemInfo(&SysInfo);
    ulCurrAddr = (UINT_PTR)SysInfo.lpMinimumApplicationAddress;

    while (sizeof(Mbi) == VirtualQueryEx(hProcess, (LPVOID)(ulCurrAddr), &Mbi, sizeof(Mbi)),
        (ulCurrAddr <= (UINT_PTR)(SysInfo.lpMaximumApplicationAddress)))
    {
        VirtualProtectEx(hProcess, (LPVOID)(ulCurrAddr), Mbi.RegionSize, dwReadableMask, &Mbi.Protect);
        //printf("Address: 0x%x\n", (UINT_PTR)(ulCurrAddr));
        if ((dwReadableMask & Mbi.Protect) && (FALSE == (dwProtectedMask & Mbi.Protect)))
        {
            lpBuff = (BYTE*)(malloc(Mbi.RegionSize));
            if (ReadProcessMemory(hProcess, (LPVOID)(ulCurrAddr), lpBuff, Mbi.RegionSize, &ulBytesRead) == TRUE)
            {
                if (ulBytesRead == Mbi.RegionSize)
                {
                    for (UINT i = 0; i < Mbi.RegionSize; ++i)
                    {
                        if (memcmp((LPCVOID)(lpBuff + i), DataToFind, DataSize) == 0)
                        {
                            free(lpBuff);
                            return ulCurrAddr + i;
                        }
                    }
                }
            }
            free(lpBuff);
        }
        ulCurrAddr = (UINT_PTR)(Mbi.BaseAddress) + Mbi.RegionSize;
    }
    return 1;
}

std::vector<BYTE> RBM(SIZE_T address, size_t size)
{
    std::vector<BYTE> buffer(size, 0);
    ReadProcessMemory(hProcess, (LPCVOID)address, buffer.data(), size, NULL);
    return buffer;
}

BOOL WBM(SIZE_T address, const std::vector<BYTE>& bytes)
{
    return WriteProcessMemory(hProcess, (LPVOID)address, bytes.data(), bytes.size(), NULL);
}

uintptr_t* AOB(BYTE* bytes, size_t dataSize)
{
    FOUND_ADDRESSES Addr;
    ZeroMemory(&Addr, sizeof(Addr));

    if (FALSE == FindArrayOfBytes(&Addr, bytes, dataSize, TRUE))
    {
        printf("AOB Not Found\n");
        return nullptr;
    }
    int addressesFound = Addr.NumberOfAddresses;
    printf("AOB Found: %d\n", addressesFound);
    uintptr_t* addresses = new uintptr_t[addressesFound];
    for (size_t i = 0; i < addressesFound; i++)
    {
        addresses[i] = Addr.Addresses[i];
    }
    return addresses;
}

uintptr_t AOBOne(BYTE* bytes, size_t dataSize)
{
    uintptr_t address = FindArrayOfBytesOne(bytes, dataSize);
    if (address == 1)
    {
        printf("AOB Not Found\n");
        return 1;
    }
    printf("AOB Found: %x\n", address);
    return address;
}
