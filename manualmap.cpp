#include "manualmap.h"
#include "cfg_prot.h"
#include "threadm.h"
#include <fstream>
#include "mem_prot.h"

extern CRITICAL_SECTION g_ProtectionCS;
extern ThreadManager* g_ThreadManager;

namespace Injector {
    bool ManualMap(Process::Object& proc, const std::string& Path) {
        try {
            uintptr_t TargetBase;
            IMAGE_NT_HEADERS* NtHeaders = nullptr;

            if (!details::WriteFileToProcess(proc, Path, TargetBase, NtHeaders))
                return false;

            if (!details::WhitelistExecutableRegions(proc, TargetBase, NtHeaders))
                return false;

            if (!details::SetupThreadManagement(proc, TargetBase, NtHeaders))
                return false;

            if (!details::SetupProtectionGuards(proc, TargetBase,
                NtHeaders->OptionalHeader.SizeOfImage))
                return false;

            return true;
        }
        catch (const std::exception& e) {
            // ak raghac kenit karoche ra
        }
    }

    namespace details {
        bool WriteFileToProcess(Process::Object& proc, const std::string& Path,
            uintptr_t& TargetBase, IMAGE_NT_HEADERS*& NtHeaders) {
            std::ifstream file(Path, std::ios::binary | std::ios::ate);
            if (!file.is_open()) {
                // Ver Vxsnit DLL Fails
            }

            size_t fileSize = static_cast<size_t>(file.tellg());
            file.seekg(0, std::ios::beg);
            std::vector<uint8_t> buffer(fileSize);

            if (!file.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
                // Ver Wavikitxet DLL Faili
            }

            // Parse PE headers
            IMAGE_DOS_HEADER* DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer.data());
            if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
                // Araswori DOS Headeri
            }

            NtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer.data() + DosHeader->e_lfanew);
            if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
                // Araswori NT Headeri
            }

            TargetBase = Process::details::RemoteAlloc<uintptr_t>(
                proc._handle,
                NtHeaders->OptionalHeader.SizeOfImage,
                PAGE_EXECUTE_READWRITE
            );

            Process::details::RemoteWrite(
                proc._handle,
                TargetBase,
                buffer.data(),
                NtHeaders->OptionalHeader.SizeOfHeaders
            );

            IMAGE_SECTION_HEADER* SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
            for (WORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++) {
                if (SectionHeader[i].SizeOfRawData > 0) {
                    Process::details::RemoteWrite(
                        proc._handle,
                        TargetBase + SectionHeader[i].VirtualAddress,
                        buffer.data() + SectionHeader[i].PointerToRawData,
                        SectionHeader[i].SizeOfRawData
                    );
                }
            }

            return true;
        }

        bool WhitelistExecutableRegions(Process::Object& proc, uintptr_t TargetBase,
            IMAGE_NT_HEADERS* NtHeaders) {
            Process::Module loader = proc.GetModule("RobloxPlayerBeta.dll");
            uintptr_t fnInsert = loader.Start + 0xe5c390; //setinsert
            uintptr_t mapAddr = loader.Start + 0x283ac0; //bitmap
            uintptr_t cfgCacheAddr = 0;

            Process::details::RemoteRead(
                proc._handle,
                reinterpret_cast<void*>(loader.Start + 0x299ac0), // cfgcache
                &cfgCacheAddr,
                sizeof(cfgCacheAddr)
            );

            IMAGE_SECTION_HEADER* SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
            for (WORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++) {
                if (SectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                    uintptr_t secBase = TargetBase + SectionHeader[i].VirtualAddress;
                    size_t secSize = SectionHeader[i].Misc.VirtualSize > 0 ?
                        SectionHeader[i].Misc.VirtualSize : SectionHeader[i].SizeOfRawData;

                    try {
                        cfg_prot::BatchWhitelistRegion(
                            proc._handle,
                            fnInsert,
                            mapAddr,
                            secBase,
                            secSize
                        );

                        if (cfgCacheAddr) {
                            cfg_prot::PatchCFGCache(
                                proc._handle,
                                cfgCacheAddr,
                                secBase,
                                secSize
                            );
                        }
                    }
                    catch (...) {
                        cfg_prot::mtavari::Whitelist(
                            proc._handle,
                            secBase,
                            secSize
                        );

                        if (cfgCacheAddr) {
                            cfg_prot::mtavari::Cache(
                                proc._handle,
                                secBase,
                                secSize
                            );
                        }
                    }
                }
            }

            cfg_prot::BatchWhitelistRegion(
                proc._handle,
                fnInsert,
                mapAddr,
                TargetBase,
                NtHeaders->OptionalHeader.SizeOfImage
            );

            return true;
        }

        bool SetupThreadManagement(Process::Object& proc, uintptr_t TargetBase,
            IMAGE_NT_HEADERS* NtHeaders) {
            InitializeCriticalSection(&g_ProtectionCS);

            g_ThreadManager = new ThreadManager(
                proc._handle,
                TargetBase,
                NtHeaders->OptionalHeader.SizeOfImage
            );

            for (int i = 0; i < 3; i++) {
                g_ThreadManager->CreateHiddenThread();
            }

            g_ThreadManager->CamouflageThreads();
            return true;
        }

        bool SetupProtectionGuards(Process::Object& proc, uintptr_t TargetBase,
            size_t ImageSize) {
            Protection::memguard::StartPageGuardian(proc._handle, TargetBase, ImageSize);
            Protection::memguard::StartSectionGuardian(proc._handle, TargetBase, ImageSize);
            Protection::memguard::StartCFGCacheGuardian(proc._handle, TargetBase, ImageSize);

            Protection::threadguard::StartThreadMonitor(proc._handle, TargetBase, ImageSize);

            return true;
        }
    }
}