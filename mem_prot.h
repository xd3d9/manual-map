#pragma once
#define NOMINMAX
#include <Windows.h>
#include <vector>

namespace Protection {
    class memguard {
    public:
        static void StartPageGuardian(HANDLE hProcess, uintptr_t base, size_t size);
        static void StartSectionGuardian(HANDLE hProcess, uintptr_t base, size_t size);
        static void StartCFGCacheGuardian(HANDLE hProcess, uintptr_t base, size_t size);

        void Cleanup();

    private:
        static DWORD WINAPI PageGuardianThread(LPVOID lpParam);
        static DWORD WINAPI SectionGuardianThread(LPVOID lpParam);
        static DWORD WINAPI CFGCacheGuardianThread(LPVOID lpParam);
    };

    class threadguard {
    public:
        static void StartThreadMonitor(HANDLE hProcess, uintptr_t base, size_t size);

    private:
        static DWORD WINAPI MonitorThread(LPVOID lpParam);
    };
}