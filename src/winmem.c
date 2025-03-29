#include "winmem.h"

typedef enum {
    WINMEM_SNAPPROCESS, // Callback type for processes
    WINMEM_SNAPTHREAD,  // Callback type for threads
    WINMEM_SNAPMODULE   // Callback type for modules
} SnapshotType;

typedef struct {
    SnapshotType type;
    void *entry;
} Snapshot;

typedef enum {
    WINMEM_LOG_INFO,    // Informational log level
    WINMEM_LOG_WARNING, // Warning log level
    WINMEM_LOG_ERROR    // Error log level
} LogLevel;

typedef struct {
    DWORD   processID;      // Process ID associated with the window
    HWND    hwnd;           // Handle to the window
} WindowData;

typedef struct {
    LPCSTR       nameToFind; // Name of the process to find
    DWORD        idToFind;   // Process ID to find
    pProcessInfo info;       // Pointer to store process information
} FindProcessData;

typedef struct {
    DWORD       processID;  // Process ID associated with the thread
    DWORD       idToFind;   // Thread ID to find
    pThreadInfo info;       // Pointer to store thread information
} FindThreadData;

typedef struct {
    LPCSTR      nameToFind;
    pModuleInfo info;
} FindModuleData;

typedef struct {
    EnumThreadsCallback callback;
    void *userData;
} EnumThreadData;

typedef struct {
    EnumProcessesCallback callback;
    void *userData;
} EnumProcessData;

typedef struct {
    EnumModulesCallback callback;
    void *userData;
} EnumModuleData;

typedef BOOL (*SnapshotCallback)(Snapshot*, void*);
typedef BOOL (*SnapshotFirstFunc)(HANDLE, void*);
typedef BOOL (*SnapshotNextFunc)(HANDLE, void*);

int _wmLogImpl(LogLevel level, const char *funcName, const char *const _Format, ...) {
    va_list args;
    va_start(args, _Format);
    const char* levelStr;
    int result = 0;
    void *outstream = NULL;

    switch (level) {
        case WINMEM_LOG_INFO:
            levelStr = "INFO";
            outstream = stdout;
            break;

        case WINMEM_LOG_WARNING:
            levelStr = "WARNING";
            outstream = stdout;
            break;
            
        case WINMEM_LOG_ERROR:
            levelStr = "ERROR";
            outstream = stderr;
            break;

        default:
            levelStr = "MESSAGE";
            outstream = stdout;
            break;
    }
    
    fprintf_s(outstream, "[%s] [%s] ", levelStr, funcName);
    result = vfprintf_s(outstream, _Format, args);
    fprintf_s(outstream, "\n");
    va_end(args);
    return result; // returnы amount of chars
}

#if 1
    #define wmLog(level, _Format, ...) _wmLogImpl(level, __FUNCTION__, _Format, ##__VA_ARGS__)
#else
    #define wmLog(...)
#endif

void _FillThreadInfo(pThreadInfo info, PTHREADENTRY32 entry) {
    info->threadID = entry->th32ThreadID;
    info->ownerProcessID = entry->th32OwnerProcessID;
    info->basePriority = entry->tpBasePri;
}

void _FillProcessInfo(pProcessInfo info, PPROCESSENTRY32 entry) {
    strcpy_s(info->exePath, MAX_PATH, entry->szExeFile);
    info->parentProcessID = entry->th32ParentProcessID;
    info->processID = entry->th32ProcessID;
    info->threadCount = entry->cntThreads;
}

void _FillModuleInfo(pModuleInfo info, PMODULEENTRY32 entry) {
    strcpy_s(info->name, MAX_MODULE_NAME32 + 1, entry->szModule);
    info->processID = entry->th32ProcessID;
    info->baseAddress = entry->modBaseAddr;
    info->baseSize = entry->modBaseSize;
    info->hModule = entry->hModule;
    return;
}
        
BOOL _EnumSnapshotsCallback(Snapshot *snapshot, void *userData) {
    if (snapshot == NULL) return FALSE;
    if (snapshot->entry == NULL) return FALSE;

    switch (snapshot->type) {
        case WINMEM_SNAPPROCESS: {
            PPROCESSENTRY32 entry = (PPROCESSENTRY32)snapshot->entry;
            EnumProcessData *data = (EnumProcessData*)userData;
            ProcessInfo info = {0};
            _FillProcessInfo(&info, entry);
            return data->callback(&info, data->userData);
        } break;

        case WINMEM_SNAPTHREAD: {
            PTHREADENTRY32 entry = (PTHREADENTRY32)snapshot->entry; 
            EnumThreadData *data = (EnumThreadData*)userData;
            ThreadInfo info = {0};
            _FillThreadInfo(&info, entry);
            return data->callback(&info, data->userData);
        } break;

        case WINMEM_SNAPMODULE: {
            PMODULEENTRY32 entry = (PMODULEENTRY32)snapshot->entry; 
            EnumModuleData *data = (EnumModuleData*)userData;
            ModuleInfo info = {0};
            _FillModuleInfo(&info, entry);
            return data->callback(&info, data->userData);
        } break;

        default:
            return FALSE;
    }
}

BOOL _FindProcessByNameCallback(Snapshot *snapshot, void *userData) {
    if (snapshot == NULL) return FALSE;
    PPROCESSENTRY32 procEntry = (PPROCESSENTRY32)snapshot->entry;
    FindProcessData *data = (FindProcessData*)userData;
    if (_stricmp(data->nameToFind, procEntry->szExeFile) == 0) {
        data->idToFind = procEntry->th32ProcessID;
        wmLog(WINMEM_LOG_INFO, "Process found: %s", data->nameToFind);
        return FALSE;
    }
    wmLog(WINMEM_LOG_INFO, "Checking process: %s", procEntry->szExeFile);
    return TRUE;
}

BOOL _TraverseSnapshots(DWORD dwFlags, DWORD th32ProcessID, size_t dwSize,
    SnapshotFirstFunc First32, SnapshotNextFunc Next32, Snapshot *snapshot,
    SnapshotCallback callback, void *userData) {

    if (First32 == NULL || Next32 == NULL ) {
        wmLog(WINMEM_LOG_ERROR, "Invalid function pointers provided.");
        return FALSE;
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(dwFlags, th32ProcessID);
    if (INVALID_HANDLE_VALUE == hSnapshot) {
        wmLog(WINMEM_LOG_ERROR, "Failed create snapshot. Code: %lu", GetLastError());
        return FALSE;
    }

    snapshot->entry = calloc(1, dwSize);
    if (snapshot->entry == NULL) {
        CloseHandle(hSnapshot);
        wmLog(WINMEM_LOG_ERROR, 
            "Failed to allocate memory for snapshot entry. Requested size: %zu bytes.", dwSize);
        return FALSE;
    }

    // important to set size dwSize of a structure
    *(DWORD*)snapshot->entry = dwSize;
    if (!First32(hSnapshot, snapshot->entry)) {
        CloseHandle(hSnapshot);
        free(snapshot->entry);
        wmLog(WINMEM_LOG_ERROR, "Failed to retrieve entry. Code: %lu", GetLastError());
        return FALSE;
    }

    do {
        if (!callback(snapshot, userData)) {
            CloseHandle(hSnapshot);
            free(snapshot->entry);
            return TRUE;
        }
    } while (Next32(hSnapshot, snapshot->entry));

    CloseHandle(hSnapshot);
    free(snapshot->entry);
    return FALSE;
}

BOOL _TraverseProcesses(DWORD processID, SnapshotCallback callback, void *userData) {
    Snapshot snapshot = {.type = WINMEM_SNAPPROCESS};
    return _TraverseSnapshots(
        TH32CS_SNAPPROCESS,
        processID,
        sizeof(PROCESSENTRY32),
        (SnapshotFirstFunc)Process32First,
        (SnapshotNextFunc)Process32Next,
        &snapshot,
        callback,
        userData
    );
}

BOOL _TraverseThreads(DWORD processID, SnapshotCallback callback, void *userData) {
    Snapshot snapshot = {.type = WINMEM_SNAPTHREAD};
    return _TraverseSnapshots(
        TH32CS_SNAPTHREAD,
        processID,
        sizeof(THREADENTRY32),
        (SnapshotFirstFunc)Thread32First,
        (SnapshotNextFunc)Thread32Next,
        &snapshot,
        callback,
        userData
    );
}

BOOL _TraverseModules(DWORD processID, SnapshotCallback callback, void *userData) {
    Snapshot snapshot = {.type = WINMEM_SNAPMODULE};
    return _TraverseSnapshots(
        TH32CS_SNAPMODULE,
        processID,
        sizeof(MODULEENTRY32),
        (SnapshotFirstFunc)Module32First,
        (SnapshotNextFunc)Module32Next,
        &snapshot,
        callback,
        userData
    );
}

// winapi callback function
BOOL CALLBACK _EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
    if (hwnd == NULL) return FALSE;
    WindowData *pWindata = (WindowData*)lParam;
    DWORD winPid = 0;
    GetWindowThreadProcessId(hwnd, &winPid);
    if (winPid == pWindata->processID) { 
        pWindata->hwnd = hwnd;
        return FALSE;
    }
    return TRUE;
}

BOOL _GetSnapshotInfoCallback(Snapshot *snapshot, void *userData) {
    if (snapshot == NULL) return FALSE;
    if (snapshot->entry == NULL) {
        wmLog(WINMEM_LOG_ERROR, "Invalid snapshot entry buffer.");
        return FALSE;
    }

    SnapshotType type = snapshot->type;
    switch (type) {
        case WINMEM_SNAPTHREAD: {
            PTHREADENTRY32 entry = (PTHREADENTRY32)snapshot->entry;
            FindThreadData *data = (FindThreadData*)userData;
            if (data->processID == entry->th32OwnerProcessID) {
                if (data->idToFind == entry->th32ThreadID || data->idToFind == 0) {
                    /**
                     * Fill entry if thread id is found
                     * otherwise do nothing
                     */
                    _FillThreadInfo(data->info, entry);
                    wmLog(WINMEM_LOG_INFO, "Found thread -> ID: %lu", entry->th32ThreadID);
                    return FALSE;
                }
                wmLog(WINMEM_LOG_INFO, "Checking thread -> ID: %lu", entry->th32ThreadID);
            }
            return TRUE;
        }

        case WINMEM_SNAPPROCESS: {
            PPROCESSENTRY32 entry = (PPROCESSENTRY32)snapshot->entry;
            FindProcessData *data = (FindProcessData*)userData;
            if (data->idToFind == entry->th32ProcessID || 
                (_stricmp(data->nameToFind, entry->szExeFile) == 0))
            {
                _FillProcessInfo(data->info, entry);
                wmLog(WINMEM_LOG_INFO, "Found process -> ID: %lu", entry->th32ProcessID);
                return FALSE;
            }
            wmLog(WINMEM_LOG_INFO, "Checking process -> ID: %lu", entry->th32ProcessID);
            return TRUE;
        }

        case WINMEM_SNAPMODULE: {
            PMODULEENTRY32 entry = (PMODULEENTRY32)snapshot->entry;
            FindModuleData *data = (FindModuleData*)userData;
            if (_stricmp(data->nameToFind, entry->szModule) == 0)
            {
                _FillModuleInfo(data->info, entry);
                wmLog(WINMEM_LOG_INFO, "Found module -> Name: %s", entry->szModule);
                return FALSE;
            }
            wmLog(WINMEM_LOG_INFO, "Checking module -> Name: %s", entry->szModule);
            return TRUE;
        }
    }
    return FALSE;
}

HWND GetWindowByName(LPCSTR windowName) {
    if (windowName == NULL) return NULL;
    HWND hwnd = FindWindow(NULL, windowName);
    if (hwnd == NULL) {
        wmLog(WINMEM_LOG_ERROR, "Window not found %s", windowName);
        return INVALID_HANDLE_VALUE;
    }
    wmLog(WINMEM_LOG_INFO, "Window found %s", windowName);
    return hwnd;
}

HWND GetWindowByPID(DWORD processID) {
    if (processID <= 0) return NULL;
    WindowData windata = { processID, NULL };
    EnumWindows(_EnumWindowsCallback, (LPARAM)&windata);
    if (windata.hwnd == NULL) {
        wmLog(WINMEM_LOG_ERROR, "Window process not found p%lu", processID);
        return NULL;
    }
    wmLog(WINMEM_LOG_INFO, "Window process found %lu", processID);
    return windata.hwnd;
}

DWORD GetPIDByName(LPCSTR processName) {
    if (processName == NULL) return 0;

    FindProcessData procData = { processName, 0, NULL};
    if (!_TraverseProcesses(0, _FindProcessByNameCallback, &procData)) {
        wmLog(WINMEM_LOG_ERROR, "Process not found: %s", processName);
        return 0;
    }

    wmLog(WINMEM_LOG_INFO, "Process found: %s", processName);
    return procData.idToFind;
}

DWORD GetPIDByWindowName(LPCSTR windowName) {
    if (windowName == NULL) return FALSE;
    DWORD processID;
    HWND hWindow = FindWindow(NULL, windowName);

    if (hWindow == NULL) {
        wmLog(WINMEM_LOG_ERROR, "Window does not exist: %s", windowName);
        return 0;
    }

    GetWindowThreadProcessId(hWindow, &processID);
    wmLog(WINMEM_LOG_INFO, "Process %lu found in window: %s", processID, windowName);
    return processID;
}

// TODO: code repetition can be reduced here
// should be like: GetSnapshotInfo(void *IdOrName, DWORD processID, void *info)
BOOL GetThreadInfo(DWORD threadID, DWORD processID, pThreadInfo info) {
    if (info == NULL) return FALSE;
    if (processID == 0) return FALSE;
    FindThreadData data = { .processID = processID, .idToFind = threadID, .info = info };
    if (!_TraverseThreads(0, _GetSnapshotInfoCallback, &data)) {
        wmLog(WINMEM_LOG_ERROR, "Thread not found: %d", threadID);
        return FALSE;
    } else {
        if (threadID != 0) {
            wmLog(WINMEM_LOG_INFO, "Thread found: %d", threadID);
            return TRUE;
        }
    }
    return FALSE;
}

BOOL GetProcessInfo(LPCSTR processName, DWORD processID, pProcessInfo info) {
    if (info == NULL) return FALSE;
    if (processID == 0 && processName == NULL) return FALSE;
    FindProcessData data = { .idToFind = processID, .nameToFind = processName, .info = info };
    if (!_TraverseProcesses(0, _GetSnapshotInfoCallback, &data)) {
        wmLog(WINMEM_LOG_ERROR, "Process not found: %d", processID);
        return FALSE;
    } else {
        wmLog(WINMEM_LOG_INFO, "Process found: %d", processID);
        return TRUE;
    }
    return FALSE;
}

BOOL GetModuleInfo(LPCSTR moduleName, DWORD processID, pModuleInfo info) {
    if (moduleName == NULL) return FALSE;
    if (processID == 0) return FALSE;
    if (info == NULL) return FALSE;
    FindModuleData data = { .nameToFind = moduleName, .info = info };
    if (!_TraverseModules(processID, _GetSnapshotInfoCallback, &data)) {
        wmLog(WINMEM_LOG_ERROR, "Module not found: %s", moduleName);
        return FALSE;
    } else {
        wmLog(WINMEM_LOG_INFO, "Module found: %s", moduleName);
        return TRUE;
    }
    return FALSE;
}

HANDLE AttachByPID(DWORD processID, DWORD access) {
    if (processID == 0) { return INVALID_HANDLE_VALUE; }

    HANDLE process = OpenProcess(access, FALSE, processID);
    if (INVALID_HANDLE_VALUE != process) {
        wmLog(WINMEM_LOG_INFO, "Successfully attached to %lu", processID);
        return process;
    }

    wmLog(WINMEM_LOG_ERROR, "Cannot attach to process");
    return INVALID_HANDLE_VALUE;
}

HANDLE AttachByName(LPCSTR processName, DWORD access) {
    if (processName == NULL) { return INVALID_HANDLE_VALUE; }

    HANDLE process = NULL;
    DWORD processID = GetPIDByName(processName);
    if (processID <= 0) {
        wmLog(WINMEM_LOG_ERROR, "Cannot attach to process");
        return INVALID_HANDLE_VALUE;
    }

    process = OpenProcess(access, FALSE, processID);
    if (INVALID_HANDLE_VALUE != process) {
        wmLog(WINMEM_LOG_INFO, "Successfully attached to %lu, %s", processID, processName);
    }

    return process;
}

HANDLE AttachByWindowName(LPCSTR windowName, DWORD access) {
    if (windowName == NULL) { return INVALID_HANDLE_VALUE; }
    HANDLE process = NULL;
    DWORD processID = GetPIDByWindowName(windowName);
    if (processID <= 0) {
        wmLog(WINMEM_LOG_ERROR, "Cannot attach to process");
        return INVALID_HANDLE_VALUE;
    }
    process = OpenProcess(access, FALSE, processID);
    wmLog(WINMEM_LOG_INFO, "Successfully attached to %lu in window_%s", processID, windowName);
    return process;
}

HANDLE AttachByWindow(HWND hWindow, DWORD access) {
    if (hWindow == NULL) { return INVALID_HANDLE_VALUE; }
    HANDLE process = NULL;
    DWORD processID = 0;
    GetWindowThreadProcessId(hWindow, &processID);
    if (processID <= 0) {
        wmLog(WINMEM_LOG_ERROR, "Cannot attach to process");
        return INVALID_HANDLE_VALUE;
    }
    process = OpenProcess(access, FALSE, processID);
    wmLog(WINMEM_LOG_INFO, "Successfully attached in window_%d", hWindow);
    return process;
}

void Deattach(HANDLE hProcess) {
    if (INVALID_HANDLE_VALUE == hProcess) {
        wmLog(WINMEM_LOG_ERROR, "Handle does not exist.");
        return;
    }
    CloseHandle(hProcess);
    wmLog(WINMEM_LOG_INFO, "Process deattached.");
}

BOOL EnumThreads(EnumThreadsCallback callback, void *userData) {
    if (callback == NULL) return FALSE;

    EnumThreadData data = {.callback = callback, .userData = userData};
    if (_TraverseThreads(0, _EnumSnapshotsCallback, &data)) {
        return TRUE;
    }
    return FALSE;
}

BOOL EnumProcesses(EnumProcessesCallback callback, void *userData) {
    if (callback == NULL) return FALSE;
    
    EnumProcessData data = {.callback = callback, .userData = userData};
    if (_TraverseProcesses(0, _EnumSnapshotsCallback, &data)) {
        return TRUE;
    }
    return FALSE;
}

BOOL EnumModules(DWORD processID, EnumModulesCallback callback, void *userData) {
    if (processID == 0 || callback == NULL) return FALSE;

    EnumModuleData data = {.callback = callback, .userData = userData};
    if (_TraverseModules(processID, _EnumSnapshotsCallback, &data)) {
        return TRUE;
    }
    return FALSE;
}

SIZE_T GetMemoryInfo(HANDLE hProcess, LPCVOID address, PMEMORY_BASIC_INFORMATION buffer) {
    if (hProcess == INVALID_HANDLE_VALUE || address == NULL || buffer == NULL) return 0;
    return VirtualQueryEx(hProcess, address, buffer, sizeof(MEMORY_BASIC_INFORMATION));
}

UINT_PTR GetModuleBaseAddress(DWORD processID, LPCSTR name) {
    if (name == NULL || processID == 0) return 0;

    ModuleInfo info = {0};
    if(GetModuleInfo(name, processID, &info)) {
        return (UINT_PTR)info.baseAddress;
    }
    return 0;
}

BOOL IsMemoryProtected(HANDLE hProcess, LPCVOID address, DWORD protectionFlag) {
    MEMORY_BASIC_INFORMATION mbi = {0};
    if (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == 0) {
        wmLog(WINMEM_LOG_ERROR, "VirtualQueryEx failed for address %p. Error code: %lu", address, GetLastError());
        return FALSE;
    }

    if (mbi.State != MEM_COMMIT) {
        wmLog(WINMEM_LOG_WARNING, "Memory at %p is not committed (State: 0x%X)", address, mbi.State);
        return FALSE;
    }

    BOOL isProtected = FALSE;

    switch (protectionFlag) {
        case WINMEM_CANREAD:
            isProtected = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) != 0;
            break;
        case WINMEM_CANWRITE:
            isProtected = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) != 0;
            break;
        case WINMEM_NOACCESS:
            isProtected = (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0;
            break;
        default:
            isProtected = (mbi.Protect & protectionFlag) != 0;
            break;
    }

    wmLog(WINMEM_LOG_INFO, "Memory at %p: Protect=0x%X, Requested=0x%X, Protected=%d",
          address, mbi.Protect, protectionFlag, isProtected);

    return isProtected;
}

BOOL ProtectMemory(HANDLE hProcess, LPVOID address, SIZE_T size, DWORD newProtect, PDWORD pOldProtect) {
    if (hProcess == INVALID_HANDLE_VALUE || address == NULL || size == 0 || newProtect == 0 || pOldProtect == NULL) {
        return FALSE;
    }

    if (VirtualProtectEx(hProcess, address, size, newProtect, pOldProtect)) {
        wmLog(WINMEM_LOG_INFO, "Memory protection flag changed at %p to %zu", address, newProtect);
        return TRUE;
    }

    wmLog(WINMEM_LOG_INFO, "Failed to set memory protection at %p. Error code: %lu", address, GetLastError());
    return FALSE;
}

SIZE_T ReadMemory(HANDLE hProcess, LPCVOID address, LPVOID buffer, SIZE_T size) {
    if (hProcess == INVALID_HANDLE_VALUE || address == NULL || buffer == NULL || size == 0) return 0;

    SIZE_T bytesRead = 0;
    DWORD oldProtect = 0;
    BOOL isProtected = FALSE;
    BOOL canRead = TRUE;
    MEMORY_BASIC_INFORMATION mbi = {0};
    if (!IsMemoryProtected(hProcess, address, WINMEM_CANREAD)) {
        canRead = FALSE;
        GetMemoryInfo(hProcess, (LPVOID)address, &mbi);
        wmLog(WINMEM_LOG_INFO, "Cannot read from memory page %p", mbi.BaseAddress);
        wmLog(WINMEM_LOG_INFO, "Trying to change memory page %p protection", mbi.BaseAddress);
        if (VirtualProtectEx(hProcess, (LPVOID)mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProtect)) {
            wmLog(WINMEM_LOG_INFO, "Memory page %p protection changed: 0x%X", mbi.BaseAddress, WINMEM_CANWRITE);
            isProtected = TRUE;
            canRead = TRUE;
        }
    }

    if (canRead) {
        if (ReadProcessMemory(hProcess, address, buffer, size, &bytesRead)) {
            wmLog(WINMEM_LOG_INFO, "Read %zu bytes from address %p", bytesRead, address);
        }
    }

    if (isProtected) {
        DWORD temp;
        if(VirtualProtectEx(hProcess, (LPVOID)mbi.BaseAddress, mbi.RegionSize, oldProtect, &temp)) {
            isProtected = FALSE;
            wmLog(WINMEM_LOG_INFO, "Memory page %p protection restored: 0x%X", mbi.BaseAddress, oldProtect);
        }
    }

    if (bytesRead <= 0) {
        wmLog(WINMEM_LOG_ERROR, "Failed to read %zu bytes from address %p. Error code: %lu", size, address, GetLastError());
    }
    
    return bytesRead;
}

SIZE_T WriteMemory(HANDLE hProcess, LPVOID address, LPVOID buffer, SIZE_T size) {
    if (hProcess == INVALID_HANDLE_VALUE || address == NULL || buffer == NULL || size == 0) return 0;

    SIZE_T bytesWritten = 0;
    DWORD oldProtect = 0;
    BOOL isProtected = FALSE;
    BOOL canWrite = TRUE;
    MEMORY_BASIC_INFORMATION mbi = {0};
    if (!IsMemoryProtected(hProcess, address, WINMEM_CANWRITE)) {
        canWrite = FALSE;
        GetMemoryInfo(hProcess, (LPCVOID)address, &mbi);
        wmLog(WINMEM_LOG_INFO, "Cannot write to memory page %p", mbi.BaseAddress);
        wmLog(WINMEM_LOG_INFO, "Trying to change memory page %p protection", mbi.BaseAddress);
        if (VirtualProtectEx(hProcess, (LPVOID)mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProtect)) {
            wmLog(WINMEM_LOG_INFO, "Memory page %p protection changed: 0x%X", mbi.BaseAddress, WINMEM_CANWRITE);
            isProtected = TRUE;
            canWrite = TRUE;
        }
    }

    if (canWrite) {
        if (WriteProcessMemory(hProcess, address, buffer, size, &bytesWritten)) {
            wmLog(WINMEM_LOG_INFO, "Write %zu bytes to address %p", bytesWritten, address);
        }
    }

    if (isProtected) {
        DWORD temp;
        if(VirtualProtectEx(hProcess, (LPVOID)mbi.BaseAddress, mbi.RegionSize, oldProtect, &temp)) {
            wmLog(WINMEM_LOG_INFO, "Memory page %p protection restored: 0x%X", mbi.BaseAddress, oldProtect);
            isProtected = FALSE;
        }
    }

    if (bytesWritten <= 0) {
        wmLog(WINMEM_LOG_ERROR, "Failed to write %zu bytes to address %p. Error code: %lu", size, address, GetLastError());
    }

    return bytesWritten;
}

UINT_PTR PatternScan(HANDLE hProcess, BYTE *pattern, SIZE_T size) {
    if (hProcess == INVALID_HANDLE_VALUE || pattern == NULL || size == 0) return 0;

    SYSTEM_INFO sysInfo = {0};
    GetSystemInfo(&sysInfo);

    const SIZE_T pageSize = sysInfo.dwPageSize;
    // using overlap in case if pattern is between two memory pages
    const SIZE_T overlap = size > 1 ? size-1 : 0;

    BYTE *buffer = (BYTE*)malloc(pageSize + overlap);
    if (!buffer) {
        wmLog(WINMEM_LOG_ERROR, "Failed to allocate buffer");
        return 0;
    }

    UINT_PTR curPageAddress = (UINT_PTR)sysInfo.lpMinimumApplicationAddress;
    UINT_PTR maxAddress = (UINT_PTR)sysInfo.lpMaximumApplicationAddress;

    while ((curPageAddress <= (UINT_PTR)maxAddress)) {
        MEMORY_BASIC_INFORMATION mbi = {0};
        if (!VirtualQueryEx(hProcess, (LPCVOID)curPageAddress, &mbi, sizeof(mbi))) {
            wmLog(WINMEM_LOG_ERROR, "Page scanning searching error. Error code: %lu", GetLastError());
            break;
        }

        // updating page address in case page is not available
        curPageAddress = (UINT_PTR)mbi.BaseAddress + mbi.RegionSize;

        wmLog(WINMEM_LOG_INFO, "Searching for pattern on page %p", curPageAddress);

        if (mbi.State != MEM_COMMIT) {
            wmLog(WINMEM_LOG_WARNING, "Page %p memory is free or reserved", curPageAddress);
            continue;
        }

        DWORD oldProtect = 0;
        BOOL protectionChanged = FALSE;
        if ((mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) == 0) {
            if (VirtualProtectEx(hProcess, (LPVOID)mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProtect)) {
                protectionChanged = TRUE;
            } else {
                wmLog(WINMEM_LOG_WARNING, "Cannot change protection for page %p. Error: %lu", mbi.BaseAddress, GetLastError());
                continue;
            }
        }

        UINT_PTR regionBase = (UINT_PTR)mbi.BaseAddress;
        UINT_PTR regionEnd = regionBase + mbi.RegionSize;
        UINT_PTR curAddress = regionBase;

        while (curAddress < regionEnd) {
            SIZE_T bytesToRead = min(pageSize + overlap, regionEnd - curAddress);
            SIZE_T bytesRead = 0;
            BOOL rpmResult = ReadProcessMemory(hProcess, (LPCVOID)curAddress, (LPVOID)buffer, bytesToRead, &bytesRead);
            if (!rpmResult || bytesRead == 0) break;

            if (bytesRead >= size) {
                BYTE firstByte = pattern[0];
                for (SIZE_T i = 0; i < bytesRead; ++i) {
                    // important to check first byte to prevent calling memcmp to many times
                    if (buffer[i] == firstByte && memcmp(buffer + i, pattern, size) == 0) {
                        if (protectionChanged) { // restoring protection back
                            DWORD temp = 0;
                            VirtualProtectEx(hProcess, (LPVOID)mbi.BaseAddress, mbi.RegionSize, oldProtect, &temp);
                        }
                        free(buffer);
                        wmLog(WINMEM_LOG_INFO, "Pattern found at %p", curAddress + i);
                        return curAddress + i;
                    }
                }
            }

            curAddress += (bytesRead > overlap) ? (bytesRead - overlap) : bytesRead;
        }
        
        if (protectionChanged) { // restoring protection back
            DWORD temp = 0;
            VirtualProtectEx(hProcess, (LPVOID)mbi.BaseAddress, mbi.RegionSize, oldProtect, &temp);
        }
    }

    free(buffer);
    wmLog(WINMEM_LOG_INFO, "Pattern not found in scanned memory");
    return 0;
}

SIZE_T ExportMemory(HANDLE hProcess, LPCVOID address, SIZE_T size) {
    if (hProcess == NULL || address == NULL || size == 0) return 0;

    char fileName[MAX_PATH];
    SIZE_T bytesExported = 0;
    SIZE_T bytesRead = 0;

    if (!IsMemoryProtected(hProcess, address, WINMEM_CANREAD)) {
        wmLog(WINMEM_LOG_ERROR, "Memory is not available %p.", address);
        return 0;
    }

    BYTE *buffer = malloc(size);
    if (buffer == NULL) {
        wmLog(WINMEM_LOG_ERROR, "Memory allocation failed.");
        return 0;
    }

    // constructing the file name string
    snprintf(fileName, sizeof(fileName), "winmem_dump_0x%p_%zu", address, size);

    FILE *file = fopen(fileName, "w");
    
    if (ReadProcessMemory(hProcess, address, buffer, size, &bytesRead) && bytesRead > 0) {
        bytesExported = fwrite(buffer, sizeof(BYTE), size, file);
        if (bytesExported <= 0) {
            free(buffer);
            wmLog(WINMEM_LOG_ERROR, "Memory export failed.");
            return 0;
        }
        wmLog(WINMEM_LOG_INFO, "Memory at %p with size of %zu exported to file.", address, size);
    }

    fclose(file);
    free(buffer);
    return bytesExported;
}