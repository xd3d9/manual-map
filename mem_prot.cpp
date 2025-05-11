#define NOMINMAX
#include "mem_prot.h""
#include <algorithm>
#include <random>
#include <vector>
#include <algorithm>
#include "Process.h"

namespace Protection {

    struct SectionInfo {
        uintptr_t address;
        size_t size;
        DWORD protection;
    };

    static std::vector<HANDLE> g_GuardianThreads;

    DWORD WINAPI memguard::PageGuardianThread(LPVOID lpParam) {
        auto* params = reinterpret_cast<std::tuple<HANDLE, uintptr_t, size_t>*>(lpParam);
        HANDLE hProcess = std::get<0>(*params);
        uintptr_t base = std::get<1>(*params);
        size_t size = std::get<2>(*params);

        //base, base+size

        uintptr_t scanOffset = 0;
        std::random_device rd;
        std::mt19937 gen(rd());

        while (true) {
            scanOffset = (scanOffset + 0x1000) % size;

            for (uintptr_t addr = base + scanOffset; addr < base + size; addr += 0x1000) {
                MEMORY_BASIC_INFORMATION mbi = {};
                if (!VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi))) {
                    continue;
                }

                if (mbi.State == MEM_COMMIT &&
                    (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) == 0) {

                    DWORD oldProtect;
                    if (VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize,
                        PAGE_EXECUTE_READWRITE, &oldProtect)) {

                        // Verify memory contents
                        std::vector<uint8_t> buffer(mbi.RegionSize);
                        SIZE_T bytesRead;
                        if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(),
                            mbi.RegionSize, &bytesRead)) {

                            WriteProcessMemory(hProcess, mbi.BaseAddress, buffer.data(),
                                bytesRead, nullptr);
                        }

                        FlushInstructionCache(hProcess, mbi.BaseAddress, mbi.RegionSize);

                        // mbi.BaseAddress, oldProtect
                        // ak davamtavret da shegvidzlia eseni gavlogot
                    }
                }

                std::uniform_int_distribution<> dist(5, 15);
                Sleep(dist(gen));
            }
        }

        delete params;
        return 0;
    }

    DWORD WINAPI memguard::SectionGuardianThread(LPVOID lpParam) {
        auto* params = reinterpret_cast<std::tuple<HANDLE, uintptr_t, size_t>*>(lpParam);
        HANDLE hProcess = std::get<0>(*params);
        uintptr_t base = std::get<1>(*params);
        size_t size = std::get<2>(*params);

        std::vector<SectionInfo> sections;
        IMAGE_DOS_HEADER dosHeader = {};
        IMAGE_NT_HEADERS ntHeaders = {};

        if (ReadProcessMemory(hProcess, (LPCVOID)base, &dosHeader, sizeof(dosHeader), nullptr) &&
            dosHeader.e_magic == IMAGE_DOS_SIGNATURE &&
            ReadProcessMemory(hProcess, (LPCVOID)(base + dosHeader.e_lfanew),
                &ntHeaders, sizeof(ntHeaders), nullptr)) {

            IMAGE_SECTION_HEADER sectionHeader;
            uintptr_t sectionAddr = base + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS);

            for (WORD i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
                if (ReadProcessMemory(hProcess, (LPCVOID)sectionAddr, &sectionHeader,
                    sizeof(sectionHeader), nullptr)) {

                    if (sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                        sections.push_back({
                            base + sectionHeader.VirtualAddress,
                            sectionHeader.Misc.VirtualSize,
                            PAGE_EXECUTE_READWRITE
                            });
                    }
                    sectionAddr += sizeof(IMAGE_SECTION_HEADER);
                }
            }
        }

        if (sections.empty()) {
            sections.push_back({ base, size, PAGE_EXECUTE_READWRITE });
        }

        std::random_device rd;
        std::mt19937 gen(rd());

        while (true) {
            for (const auto& section : sections) {
                DWORD oldProtect;
                if (VirtualProtectEx(hProcess, (LPVOID)section.address,
                    section.size, section.protection, &oldProtect)) {

                    if (oldProtect != section.protection) {
                        //section.address, section.size
                        //gamovasworet seqcia da ak shegvidzlia shevinaxot informacia an chamovwerot

                        std::vector<uint8_t> buffer(std::min(section.size, (size_t)0x1000));
                        SIZE_T bytesRead;
                        if (ReadProcessMemory(hProcess, (LPCVOID)section.address,
                            buffer.data(), buffer.size(), &bytesRead)) {

                            WriteProcessMemory(hProcess, (LPVOID)section.address,
                                buffer.data(), bytesRead, nullptr);
                        }
                    }
                }

                std::uniform_int_distribution<> dist(10, 30);
                Sleep(dist(gen));
            }
            Sleep(50);
        }

        delete params;
        return 0;
    }

    DWORD WINAPI memguard::CFGCacheGuardianThread(LPVOID lpParam) {
        auto* params = reinterpret_cast<std::tuple<HANDLE, uintptr_t, size_t>*>(lpParam);
        HANDLE hProcess = std::get<0>(*params);
        uintptr_t base = std::get<1>(*params);
        size_t size = std::get<2>(*params);

        //base, base + size

        uintptr_t cfgCacheAddr = 0;
        Process::Module robloxModule;
        try {
            robloxModule = Process::Object(hProcess, GetProcessId(hProcess))
                .GetModule("RobloxPlayerBeta.dll");
            Process::details::RemoteRead(hProcess,
                (LPCVOID)(robloxModule.Start + 0x299ac0), // cfgcache
                &cfgCacheAddr, sizeof(cfgCacheAddr));
        }
        catch (...) {
            cfgCacheAddr = 0;
        }

        std::vector<uintptr_t> updatedPages;
        std::random_device rd;
        std::mt19937 gen(rd());

        while (true) {
            if (updatedPages.size() > 1000) {
                updatedPages.clear();
            }

            MEMORY_BASIC_INFORMATION mbi = {};
            for (uintptr_t addr = base; addr < base + size; addr += mbi.RegionSize) {
                if (!VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi))) {
                    continue;
                }

                if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD)) {
                    continue;
                }

                for (uintptr_t page = (uintptr_t)mbi.BaseAddress;
                    page < (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
                    page += 0x1000) {

                    if (std::find(updatedPages.begin(), updatedPages.end(), page) != updatedPages.end()) {
                        continue;
                    }

                    if (cfgCacheAddr) {
                        uintptr_t pageAligned = page & ~0xFFFF;
                        uintptr_t entry = cfgCacheAddr + (pageAligned >> 0x13);
                        uint32_t bit = 1 << (((pageAligned >> 0x10) & 7) % 32);

                        uint32_t current = 0;
                        if (ReadProcessMemory(hProcess, (LPCVOID)entry, &current, sizeof(current), nullptr)) {
                            if ((current & bit) == 0) {
                                uint32_t newValue = current | bit;
                                if (WriteProcessMemory(hProcess, (LPVOID)entry, &newValue, sizeof(newValue), nullptr)) {
                                    updatedPages.push_back(page);
                                    // cfg gavasworet (pageAligned)
                                }
                            }
                        }
                    }
                    std::uniform_int_distribution<> dist(1, 5);
                    Sleep(dist(gen));
                }
            }
            Sleep(100);
        }

        delete params;
        return 0;
    }

    void memguard::StartPageGuardian(HANDLE hProcess, uintptr_t base, size_t size) {
        auto* params = new std::tuple<HANDLE, uintptr_t, size_t>(hProcess, base, size);
        HANDLE hThread = CreateThread(nullptr, 0, PageGuardianThread, params, 0, nullptr);
        if (hThread) {
            g_GuardianThreads.push_back(hThread);
            SetThreadPriority(hThread, THREAD_PRIORITY_HIGHEST);
        }
    }

    void memguard::StartSectionGuardian(HANDLE hProcess, uintptr_t base, size_t size) {
        auto* params = new std::tuple<HANDLE, uintptr_t, size_t>(hProcess, base, size);
        HANDLE hThread = CreateThread(nullptr, 0, SectionGuardianThread, params, 0, nullptr);
        if (hThread) {
            g_GuardianThreads.push_back(hThread);
        }
    }

    void memguard::StartCFGCacheGuardian(HANDLE hProcess, uintptr_t base, size_t size) {
        auto* params = new std::tuple<HANDLE, uintptr_t, size_t>(hProcess, base, size);
        HANDLE hThread = CreateThread(nullptr, 0, CFGCacheGuardianThread, params, 0, nullptr);
        if (hThread) {
            g_GuardianThreads.push_back(hThread);
        }
    }

    void memguard::Cleanup() {
        for (HANDLE hThread : g_GuardianThreads) {
            if (hThread) {
                TerminateThread(hThread, 0);
                CloseHandle(hThread);
            }
        }
        g_GuardianThreads.clear();
    }
}