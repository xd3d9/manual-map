#include "cfg_prot.h"
#include <intrin.h>
#include <TlHelp32.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

extern "C" NTSTATUS NTAPI NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG BufferSize,
    PULONG BytesWritten);

extern "C" NTSTATUS NTAPI NtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN LPVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN LPTHREAD_START_ROUTINE StartRoutine,
    IN LPVOID Argument,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN LPVOID AttributeList);

__forceinline uintptr_t crypt(uintptr_t addr) {
    return (uintptr_t)((addr >> 0xC) ^ 0x7b822ce4);
}

namespace cfg_prot {

    using NtProtect_t = NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    static NtProtect_t pNtProtectStub = nullptr;

    HMODULE GetRemoteModuleHandle(HANDLE hProcess, const wchar_t* modName) {
        MODULEENTRY32W me32{};
        me32.dwSize = sizeof(MODULEENTRY32W);

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProcess));
        if (hSnap == INVALID_HANDLE_VALUE) return nullptr;

        if (Module32FirstW(hSnap, &me32)) {
            do {
                if (!_wcsicmp(me32.szModule, modName)) {
                    CloseHandle(hSnap);
                    return me32.hModule;
                }
            } while (Module32NextW(hSnap, &me32));
        }

        CloseHandle(hSnap);
        return nullptr;
    }

    static void* LoadSyscallStub(const char* funcName, size_t stubSize = 16) {
        wchar_t path[MAX_PATH];
        if (!GetModuleFileNameW(GetModuleHandleW(L"ntdll.dll"), path, MAX_PATH)) {
    		//
        }
        HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
                //
        }
        HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMap) {
            CloseHandle(hFile);
        }
        BYTE* base = reinterpret_cast<BYTE*>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
        if (!base) {
            CloseHandle(hMap);
            CloseHandle(hFile);
        }
        auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
        auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
        auto* expDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        auto* names = reinterpret_cast<uint32_t*>(base + expDir->AddressOfNames);
        auto* ords = reinterpret_cast<uint16_t*>(base + expDir->AddressOfNameOrdinals);
        auto* funcs = reinterpret_cast<uint32_t*>(base + expDir->AddressOfFunctions);
        BYTE* stubSrc = nullptr;
        for (uint32_t i = 0; i < expDir->NumberOfNames; i++) {
            char* name = reinterpret_cast<char*>(base + names[i]);
            if (strcmp(name, funcName) == 0) {
                uint16_t ord = ords[i];
                uint32_t rva = funcs[ord];
                stubSrc = base + rva;
                break;
            }
        }
        if (!stubSrc) {
            UnmapViewOfFile(base);
            CloseHandle(hMap);
            CloseHandle(hFile);
        }
        void* buf = VirtualAlloc(nullptr, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        memcpy(buf, stubSrc, stubSize);
        UnmapViewOfFile(base);
        CloseHandle(hMap);
        CloseHandle(hFile);
        return buf;
    }

    bool SyscallRemoteCall(HANDLE hProcess, uintptr_t fnInsert, uintptr_t mapAddr,
        uint32_t identity, uint64_t hash) {
        uint8_t stub[] = {
            0x48, 0xB8, 0,0,0,0,0,0,0,0,
            0x48, 0xB9, 0,0,0,0,0,0,0,0,
            0x48, 0xBA, 0,0,0,0,0,0,0,0,
            0x49, 0xB8, 0,0,0,0,0,0,0,0,
            0xFF, 0xD0,
            0xC3
        };

        uint8_t args[sizeof(uint32_t) + sizeof(uint64_t)]{};
        memcpy(args, &identity, sizeof(identity));
        memcpy(args + sizeof(identity), &hash, sizeof(hash));

        PVOID remoteArg = nullptr;
        SIZE_T argSize = 0x1000;
        if (NtAllocateVirtualMemory(hProcess, &remoteArg, 0, &argSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0)
            return false;

        NtWriteVirtualMemory(hProcess, remoteArg, args, sizeof(args), nullptr);

        uintptr_t remoteIdentity = reinterpret_cast<uintptr_t>(remoteArg);
        uintptr_t remoteHash = remoteIdentity + sizeof(uint32_t);

        memcpy(&stub[2], &fnInsert, sizeof(uintptr_t));
        memcpy(&stub[12], &mapAddr, sizeof(uintptr_t));
        memcpy(&stub[22], &remoteIdentity, sizeof(uintptr_t));
        memcpy(&stub[32], &remoteHash, sizeof(uintptr_t));

        PVOID remoteCode = nullptr;
        SIZE_T codeSize = 0x1000;
        if (NtAllocateVirtualMemory(hProcess, &remoteCode, 0, &codeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) != 0)
            return false;

        NtWriteVirtualMemory(hProcess, remoteCode, stub, sizeof(stub), nullptr);

        HANDLE hThread = nullptr;
        if (NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hProcess, (LPTHREAD_START_ROUTINE)remoteCode, nullptr, 0, 0, 0, 0, nullptr) != 0)
            return false;

        WaitForSingleObject(hThread, INFINITE);
        DWORD code = 0;
        GetExitCodeThread(hThread, &code);
        CloseHandle(hThread);

        return code != 0;
    }

    void BatchWhitelistRegion(HANDLE hProcess, uintptr_t insertFn, uintptr_t mapAddr,
        uintptr_t Start, size_t Size) {
        uintptr_t AlignedStart = Start & 0xfffffffffffff000;
        uintptr_t AlignedEnd = (Start + Size + 0xfff) & 0xfffffffffffff000;
        uint32_t Identity = 0xbff1e47f;
        BYTE gsFlag = 0;

        {
            auto gsAddr = static_cast<uintptr_t>(__readgsqword(0x30)) + 0x2EC;
            ReadProcessMemory(hProcess, reinterpret_cast<void*>(gsAddr), &gsFlag, 1, nullptr);
        }

        if (!(gsFlag & 0x10)) {
            BYTE newFlag = gsFlag | 0x10;
            auto gsAddr2 = static_cast<uintptr_t>(__readgsqword(0x30)) + 0x2EC;
            WriteProcessMemory(hProcess, reinterpret_cast<void*>(gsAddr2), &newFlag, 1, nullptr);
        }

        for (uintptr_t Page = AlignedStart; Page < AlignedEnd; Page += 0x1000) {
            uint64_t hash = static_cast<uint64_t>((Page >> 0xC) ^ 0x7b822ce4);
            bool success = false;
            for (int attempt = 0; attempt < 5 && !success; ++attempt) {
                success = SyscallRemoteCall(hProcess, insertFn, mapAddr, 0xbff1e47f, hash);
                if (!success) Sleep(50);
            }
        }

        BYTE finalFlag = gsFlag & ~0x10;
        auto gsAddr3 = static_cast<uintptr_t>(__readgsqword(0x30)) + 0x2EC;
        WriteProcessMemory(hProcess, reinterpret_cast<void*>(gsAddr3), &finalFlag, 1, nullptr);
    }

    void PatchCFGCache(HANDLE hProcess, uintptr_t cacheBase, uintptr_t Base, size_t Size)
    {
        uintptr_t alignedBase = Base & ~0xFFFF;
        size_t alignedSize = ((Size + 0xFFFF) / 0x10000) * 0x10000;

        for (uintptr_t offset = 0; offset < alignedSize; offset += 0x10000)
        {
            uintptr_t page = alignedBase + offset;
            uintptr_t entry = cacheBase + (page >> 0x13);
            uint32_t bit = 1 << (((page >> 0x10) & 7) % 32);
            uint32_t current = 0;

            ReadProcessMemory(hProcess, (LPCVOID)entry, &current, sizeof(current), nullptr);
            current |= bit;
            WriteProcessMemory(hProcess, (LPVOID)entry, &current, sizeof(current), nullptr);
        }
    }

    namespace mtavari {
        void Whitelist(HANDLE hProc, uintptr_t base, size_t len) {
            auto mod = GetRemoteModuleHandle(hProc, L"RobloxPlayerBeta.dll");
            if (!mod) return;

            uintptr_t fn = reinterpret_cast<uintptr_t>(mod) + 0xe5c390; //setinsert
            uintptr_t map = reinterpret_cast<uintptr_t>(mod) + 0x283ac0; //bitmap

            BatchWhitelistRegion(hProc, fn, map, base, len);

            uintptr_t low = base & ~0xFFF, high = (base + len + 0xFFF) & ~0xFFF;
            for (uintptr_t p = low; p < high; p += 0x1000) {
                auto h = crypt(p);
                bool ok = false;
                for (int t = 0; t < 3 && !ok; ++t) {
                    ok = SyscallRemoteCall(hProc, fn, map, 0xbff1e47f, h);
                    if (!ok) Sleep(50);
                }
                if (!ok) {
                    bool protOk = false;
                    DWORD oldProt = 0;
                    if (VirtualProtectEx(hProc, (LPVOID)p, 0x1000, PAGE_EXECUTE_READWRITE, &oldProt)) {
                        protOk = true;
                    }
                    if (!pNtProtectStub) {
                        pNtProtectStub = (NtProtect_t)LoadSyscallStub("NtProtectVirtualMemory");
                    }
                    if (pNtProtectStub) {
                        PVOID addrPtr = (PVOID)p;
                        SIZE_T sizePtr = 0x1000;
                        ULONG oldStubProt = 0;
                        NTSTATUS st = pNtProtectStub(hProc, &addrPtr, &sizePtr, PAGE_EXECUTE_READWRITE, &oldStubProt);
                        if (NT_SUCCESS(st)) {
                            protOk = true;
                        }
                    }
                    if (protOk) {
                        FlushInstructionCache(hProc, (LPVOID)p, 0x1000);
                    }
                    else {
                    }
                }
            }
        }

        void Cache(HANDLE hProc, uintptr_t base, size_t len) {
            auto mod = GetRemoteModuleHandle(hProc, L"RobloxPlayerBeta.dll");
            if (!mod) return;

            uintptr_t cbase = 0;
            if (!ReadProcessMemory(hProc, (void*)((uintptr_t)mod + 0x299ac0), &cbase, sizeof(cbase), nullptr) || !cbase) return;

            PatchCFGCache(hProc, cbase, base, len);
        }
    }
}