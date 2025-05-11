#pragma once
#include "process.h"

namespace Injector {
    bool ManualMap(Process::Object& proc, const std::string& Path);

    namespace details {
        bool WriteFileToProcess(Process::Object& proc, const std::string& Path,
            uintptr_t& TargetBase, IMAGE_NT_HEADERS*& NtHeaders);
        bool WhitelistExecutableRegions(Process::Object& proc, uintptr_t TargetBase,
            IMAGE_NT_HEADERS* NtHeaders);
        bool SetupThreadManagement(Process::Object& proc, uintptr_t TargetBase,
            IMAGE_NT_HEADERS* NtHeaders);
        bool SetupProtectionGuards(Process::Object& proc, uintptr_t TargetBase,
            size_t ImageSize);
    }
}