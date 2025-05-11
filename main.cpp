#include "process.h"
#include "manualmap.h"
#include "threadm.h"

CRITICAL_SECTION g_ProtectionCS;
ThreadManager* g_ThreadManager = nullptr;

int main() {
    InitializeCriticalSection(&g_ProtectionCS);

    try {
        UINT oldErrorMode = SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);

        Process::Object proc = Process::WaitForProcess(L"RobloxPlayerBeta.exe");

        std::string dllname = "melancholia.dll";

        if (Injector::ManualMap(proc, dllname)) {
            // AK UKVE DAVINJEKTDIT DA AXA VINARCHUNEBT DLLS
            while (true) {
                if (g_ThreadManager) {
                    g_ThreadManager->ReviveThreads();
                    Sleep(1000);
                }
            }
        }
        else {
            // chavflavdit
        }
    }
    catch (const std::exception& e) {
        return 1;
    }

    DeleteCriticalSection(&g_ProtectionCS);
    if (g_ThreadManager) {
        delete g_ThreadManager;
    }

    return 0;
}