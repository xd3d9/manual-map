#pragma once
#define NOMINMAX
#include <Windows.h>
#include <cstdint>

namespace cfg_prot {
    bool SyscallRemoteCall(HANDLE hProcess, uintptr_t fnInsert, uintptr_t mapAddr,
        uint32_t identity, uint64_t hash);
    void BatchWhitelistRegion(HANDLE hProcess, uintptr_t insertFn, uintptr_t mapAddr,
        uintptr_t Start, size_t Size);
    void PatchCFGCache(HANDLE hProcess, uintptr_t cacheBase, uintptr_t Base, size_t Size);

    namespace mtavari {
        void Whitelist(HANDLE hProc, uintptr_t base, size_t len);
        void Cache(HANDLE hProc, uintptr_t base, size_t len);
    }
}