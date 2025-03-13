#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <stdarg.h>

typedef struct WINMEM_INFO_THREAD {
    DWORD threadID;          // Thread ID
    DWORD ownerProcessID;    // Thread's owner process ID
    DWORD basePriority;      // Thread base priority
} ThreadInfo, *pThreadInfo;

typedef struct WINMEM_INFO_PROCESS {
    DWORD processID;         // PID
    DWORD parentProcessID;   // Process parent ID
    DWORD threadCount;       // Number of threads in this process
    CHAR exePath[MAX_PATH];  // Path to the process executable (process name)
} ProcessInfo, *pProcessInfo;

typedef struct WINMEM_INFO_MODULE {
    DWORD processID;                  // Module process ID
    BYTE *baseAddress;                // Base address of module in processID's context
    HMODULE hModule;                  // Module handle in processID's context
    CHAR name[MAX_MODULE_NAME32 + 1]; // Module name
} ModuleInfo, *pModuleInfo; 

typedef enum WINMEM_SNAPSHOT_TYPE {
    WINMEM_SNAPPROCESS, // Callback type for processes
    WINMEM_SNAPTHREAD,  // Callback type for threads
    WINMEM_SNAPMODULE   // Callback type for modules
} SnapshotType;

typedef enum WINMEM_MEMORY_PROTECTION {
    WINMEM_READONLY = PAGE_READONLY,
    WINMEM_READWRITE = PAGE_READWRITE
    // add more flags
} MemoryProtectionFlag;

typedef BOOL (*EnumThreadsCallback)(pThreadInfo, void*);
typedef BOOL (*EnumProcessesCallback)(pProcessInfo, void*);
typedef BOOL (*EnumModulesCallback)(pModuleInfo, void*);

/**
 * Finds a window by its name.
 * @param windowName The name of the window to find.
 * @return The handle to the window, or INVALID_HANDLE_VALUE if not found.
 */
HWND GetWindowByName(LPCSTR windowName);

/**
 * Finds a window by the process ID associated with it.
 * @param pid The process ID of the window to find.
 * @return The handle to the window, or NULL if not found.
 */
HWND GetWindowByPID(DWORD pid);

/**
 * Finds the process ID by the process name.
 * @param processName The name of the process to find.
 * @return The process ID, or 0 if not found.
 */
DWORD GetPIDByName(LPCSTR processName);

/**
 * Retrieves information about a thread by its ID or the ID of the process it belongs to.
 * @param threadID The ID of the thread to find (0 to find any thread in the process).
 * @param processID The ID of the process to which the thread belongs.
 * @param info A pointer to the ThreadInfo structure where the thread information will be stored.
 * @return TRUE if the thread information is successfully retrieved, FALSE otherwise.
 */
BOOL GetThreadInfo(DWORD threadID, DWORD processID, pThreadInfo info);

/**
 * Retrieves information about a process by its ID or name.
 * @param processName The name of the process to find (can be NULL if processID is provided).
 * @param processID The ID of the process to find (0 to find by name).
 * @param info A pointer to the ProcessInfo structure where the process information will be stored.
 * @return TRUE if the process information is successfully retrieved, FALSE otherwise.
 */
BOOL GetProcessInfo(LPCSTR processName, DWORD processID, pProcessInfo info);

/**
 * Retrieves information about a module by its name.
 * @param moduleName The name of the module to find (cannot be NULL).
 * @param processID The ID of the process to find (cannot be 0).
 * @param info A pointer to the ModuleInfo structure where the module information will be stored.
 * @return TRUE if the module information is successfully retrieved, FALSE otherwise.
 */
BOOL GetModuleInfo(LPCSTR moduleName, DWORD processID, pModuleInfo info);

/**
 * Finds the process ID by the window name.
 * @param windowName The name of the window to find the associated process ID.
 * @return The process ID, or 0 if not found.
 */
DWORD GetPIDByWindowName(LPCSTR windowName);

/**
 * Attaches to a process by its PID.
 * @param processId The process ID to attach to.
 * @return A handle to the process, or INVALID_HANDLE_VALUE if the attachment failed.
 */
HANDLE AttachByPID(DWORD processId, DWORD access);

/**
 * Attaches to a process by its name.
 * @param processName The name of the process to attach to.
 * @return A handle to the process, or INVALID_HANDLE_VALUE if the attachment failed.
 */
HANDLE AttachByName(LPCSTR processName, DWORD access);

/**
 * Attaches to a process by the name of its window.
 * @param windowName The name of the window associated with the process.
 * @return A handle to the process, or INVALID_HANDLE_VALUE if the attachment failed.
 */
HANDLE AttachByWindowName(LPCSTR windowName, DWORD access);

/**
 * Attaches to a process by its window handle.
 * @param hWindow The handle to the window associated with the process.
 * @return A handle to the process, or INVALID_HANDLE_VALUE if the attachment failed.
 */
HANDLE AttachByWindow(HWND hWindow, DWORD access);

/**
 * Closes the handle to a process, effectively detaching from it.
 * This function should be called to release resources after attaching to a process
 * using functions like AttachByPID, AttachByName, AttachByWindowName, or AttachByWindow.
 * 
 * @param hProcess The handle to the process to detach from.
 *                 If the handle is INVALID_HANDLE_VALUE, the function does nothing.
 */
void Deattach(HANDLE hProcess);

/**
 * Enumerates all threads in the system and calls the provided callback function for each thread.
 * @param callback A pointer to the callback function that will be called for each thread.
 * @param userData A pointer to user-defined data that will be passed to the callback function.
 * @return TRUE if the enumeration was successful, FALSE otherwise.
 */
BOOL EnumThreads(EnumThreadsCallback callback, void *userData);

/**
 * Enumerates all processes in the system and calls the provided callback function for each process.
 * @param callback A pointer to the callback function that will be called for each process.
 * @param userData A pointer to user-defined data that will be passed to the callback function.
 * @return TRUE if the enumeration was successful, FALSE otherwise.
 */
BOOL EnumProcesses(EnumProcessesCallback callback, void *userData);

/**
 * Enumerates all modules in a specified process and calls the provided callback function for each module.
 * @param processID The ID of the process whose modules are to be enumerated.
 * @param callback A pointer to the callback function that will be called for each module.
 * @param userData A pointer to user-defined data that will be passed to the callback function.
 * @return TRUE if the enumeration was successful, FALSE otherwise.
 */
BOOL EnumModules(DWORD processID, EnumModulesCallback callback, void *userData);

/**
 * Retrieves information about a memory region in a target process.
 * @param hProcess A handle to the target process.
 * @param address The address in the target process from which to retrieve memory information.
 * @param buffer A pointer to a MEMORY_BASIC_INFORMATION structure that receives the memory information.
 * @param bufferSize The size of the buffer.
 * @return The number of bytes returned in the buffer, or 0 if the function fails.
 */
SIZE_T GetMemoryInfo(HANDLE hProcess, LPCVOID address, PMEMORY_BASIC_INFORMATION buffer, SIZE_T bufferSize);

/**
 * Checks if a memory region in a target process is protected with the specified protection flag.
 * @param hProcess A handle to the target process.
 * @param address The address in the target process to check.
 * @param protectionFlag The memory protection flag to check (e.g., WINMEM_READONLY, WINMEM_READWRITE).
 * @return TRUE if the memory is protected with the specified flag, FALSE otherwise.
 */
BOOL IsMemoryProtected(HANDLE hProcess, LPCVOID address, MemoryProtectionFlag protectionFlag);

/**
 * Reads memory from a specified address in a target process.
 * @param hProcess A handle to the target process.
 * @param address The address in the target process from which to read memory.
 * @param buffer A pointer to the buffer that receives the data read from the target process.
 * @param size The number of bytes to read from the target process.
 * @param nBytesReaded A pointer to a variable that receives the number of bytes read. Can be NULL.
 * @return TRUE if the memory read operation was successful, FALSE otherwise.
 */
BOOL ReadMemory(HANDLE hProcess, LPCVOID address, LPVOID buffer, SIZE_T size, SIZE_T *nBytesReaded);

/**
 * Writes memory to a specified address in a target process.
 * @param hProcess A handle to the target process.
 * @param address The address in the target process to which to write memory.
 * @param buffer A pointer to the buffer containing the data to write.
 * @param size The number of bytes to write to the target process.
 * @param nBytesWritten A pointer to a variable that receives the number of bytes written. Can be NULL.
 * @return TRUE if the memory write operation was successful, FALSE otherwise.
 */
BOOL WriteMemory(HANDLE hProcess, LPVOID address, LPVOID buffer, SIZE_T size, SIZE_T *nBytesWritten);