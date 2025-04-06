### Information about `winmem` Library

The `winmem` library provides a set of functions to interact with Windows **x64** processes, threads, and modules. It allows you to retrieve information about running processes, threads, and modules, attach to processes, read and write memory, and enumerate system resources. Below is a brief guide on how to use the library.

---

### Key Features:
1. **Process Management**:
   - Retrieve process information by name or PID.
   - Attach to a process by PID, name, or window handle.
   - Enumerate all running processes.

2. **Thread Management**:
   - Retrieve thread information by thread ID or process ID.
   - Enumerate all threads in a process.

3. **Module Management**:
   - Retrieve module information by name or process ID.
   - Enumerate all modules in a process.

4. **Memory Management**:
   - Read and write memory in a target process.
   - Check memory protection flags.

5. **Window Management**:
   - Find windows by name or process ID.
   - Retrieve the process ID associated with a window.

---

### Usage Example:

```c
#include "winmem.h"

int main() {
    // Get the process ID by name
    DWORD pid = GetPIDByName("notepad.exe");
    if (pid == 0) {
        printf("Process not found.\n");
        return 1;
    }

    // Attach to the process
    HANDLE hProcess = AttachByPID(pid, PROCESS_ALL_ACCESS);
    if (hProcess == INVALID_HANDLE_VALUE) {
        printf("Failed to attach to process.\n");
        return 1;
    }

    // Example: Read memory from the process
    BYTE buffer[1024];
    SIZE_T bytesRead;
    LPVOID readAddress = (LPVOID)0x00400000; // Example address to read from
    if (ReadMemory(hProcess, readAddress, buffer, sizeof(buffer), &bytesRead)) {
        printf("Read %zu bytes from process memory at address %p.\n", bytesRead, readAddress);
    } else {
        printf("Failed to read memory at address %p.\n", readAddress);
    }

    // Example: Write memory to the process
    BYTE dataToWrite[] = {0x90, 0x90, 0x90}; // Example data to write (NOP instructions)
    SIZE_T bytesWritten;
    LPVOID writeAddress = (LPVOID)0x00400000; // Example address to write to
    if (WriteMemory(hProcess, writeAddress, dataToWrite, sizeof(dataToWrite), &bytesWritten)) {
        printf("Wrote %zu bytes to process memory at address %p.\n", bytesWritten, writeAddress);
    } else {
        printf("Failed to write memory at address %p.\n", writeAddress);
    }

    // Detach from the process
    Detach(hProcess);

    return 0;
}
```

---

### Additional Notes:
- **Error Handling**: Most functions log errors using the `wmLog` function, which outputs to the console. You can check the logs for detailed error information.
- **Memory Protection**: Before reading or writing memory, the library checks if the memory is protected with the appropriate flags. If the memory is not protected with these flags, the operation will fail.
- **Resource Management**: Always call `Detach` to close handles to processes when they are no longer needed to avoid resource leaks.

---

This library is useful for developers who need to interact with Windows processes at a low level, such as for debugging, memory manipulation, or process monitoring.