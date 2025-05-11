#include "threadm.h"
#include <TlHelp32.h>
#include <Psapi.h>
#include <random>
#include "winternl.h"

ThreadManager::ThreadManager(HANDLE hProcess, uintptr_t dllBase, size_t dllSize)
    : m_ProcessHandle(hProcess), m_DllBase(dllBase), m_DllSize(dllSize) {

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        fnNtSetInformationThread = (pNtSetInformationThread)GetProcAddress(ntdll, "NtSetInformationThread");
        fnNtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
        fnNtSetContextThread = (pNtSetContextThread)GetProcAddress(ntdll, "NtSetContextThread");
        fnNtGetContextThread = (pNtGetContextThread)GetProcAddress(ntdll, "NtGetContextThread");
    }
    FindEntryPoints();
}

ThreadManager::~ThreadManager() {
    std::lock_guard<std::mutex> lock(m_ThreadLock);
    for (HANDLE hThread : m_ManagedThreads) {
        if (hThread && hThread != INVALID_HANDLE_VALUE) {
            CloseHandle(hThread);
        }
    }
    m_ManagedThreads.clear();
}

void ThreadManager::FindEntryPoints() {
    IMAGE_DOS_HEADER dosHeader = {};
    IMAGE_NT_HEADERS ntHeaders = {};

    if (ReadProcessMemory(m_ProcessHandle, (LPCVOID)m_DllBase, &dosHeader, sizeof(dosHeader), nullptr) &&
        dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {

        if (ReadProcessMemory(m_ProcessHandle, (LPCVOID)(m_DllBase + dosHeader.e_lfanew),
            &ntHeaders, sizeof(ntHeaders), nullptr)) {

            uintptr_t entryPoint = m_DllBase + ntHeaders.OptionalHeader.AddressOfEntryPoint;
            m_EntryPoints.push_back(entryPoint);

            if (ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
                IMAGE_EXPORT_DIRECTORY exportDir = {};
                uintptr_t exportDirAddr = m_DllBase +
                    ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

                if (ReadProcessMemory(m_ProcessHandle, (LPCVOID)exportDirAddr,
                    &exportDir, sizeof(exportDir), nullptr)) {

                    std::vector<DWORD> functionRVAs(exportDir.NumberOfFunctions);
                    uintptr_t functionAddr = m_DllBase + exportDir.AddressOfFunctions;

                    if (ReadProcessMemory(m_ProcessHandle, (LPCVOID)functionAddr,
                        functionRVAs.data(), functionRVAs.size() * sizeof(DWORD), nullptr)) {

                        for (DWORD rva : functionRVAs) {
                            if (rva) {
                                uintptr_t funcAddr = m_DllBase + rva;
                                m_EntryPoints.push_back(funcAddr);
                            }
                        }
                    }
                }
            }

            if (m_EntryPoints.size() < 3) {
                BYTE buffer[4096];
                for (size_t offset = 0; offset < m_DllSize; offset += sizeof(buffer) - 16) {
                    SIZE_T bytesRead = 0;
                    if (ReadProcessMemory(m_ProcessHandle, (LPCVOID)(m_DllBase + offset),
                        buffer, sizeof(buffer), &bytesRead) && bytesRead > 16) {

                        for (size_t i = 0; i < bytesRead - 16; i++) {
                            if ((buffer[i] == 0x55 && buffer[i + 1] == 0x48 && buffer[i + 2] == 0x89 && buffer[i + 3] == 0xE5) ||
                                (buffer[i] == 0x48 && buffer[i + 1] == 0x83 && buffer[i + 2] == 0xEC) ||
                                (buffer[i] == 0x40 && buffer[i + 1] == 0x53) ||
                                (buffer[i] == 0x48 && buffer[i + 1] == 0x89 && buffer[i + 2] == 0x5C && buffer[i + 3] == 0x24)) {

                                uintptr_t funcAddr = m_DllBase + offset + i;
                                m_EntryPoints.push_back(funcAddr);

                                i += 16;
                            }
                        }
                    }
                }
            }
        }
    }

    if (!m_EntryPoints.empty()) {
        //printf(m_EntryPoints.size());
    }
    else {
        m_EntryPoints.push_back(m_DllBase);
        //printf((void*)m_DllBase);
    }
}

bool ThreadManager::HideThread(HANDLE hThread) {
    if (!m_ProcessHandle || !hThread) return false;

    ULONG hiddenInfo = 0x01;
    NTSTATUS status = 0xC0000001;

    if (fnNtSetInformationThread) {
        status = fnNtSetInformationThread(
            hThread,
            0x11,
            NULL,
            0
        );

        NTSTATUS statusCritical = fnNtSetInformationThread(
            hThread,
            0x1E,
            &hiddenInfo,
            sizeof(hiddenInfo)
        );

        PVOID kernelDllBase = GetModuleHandleA("kernelbase.dll");
        if (kernelDllBase) {
            PVOID fakeStartAddress = (PVOID)((ULONG_PTR)kernelDllBase + 0x12345);
            fnNtSetInformationThread(
                hThread,
                9,
                &fakeStartAddress,
                sizeof(fakeStartAddress)
            );
        }
    }

    SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);

    DWORD_PTR processAffinityMask = 0, systemAffinityMask = 0;
    if (GetProcessAffinityMask(GetCurrentProcess(), &processAffinityMask, &systemAffinityMask)) {
        DWORD_PTR affinityMask = (processAffinityMask & 2) ? 2 : 1;
        SetThreadAffinityMask(hThread, affinityMask);
    }

    return NT_SUCCESS(status);
}

HANDLE ThreadManager::CreateHiddenThread(uintptr_t entryPoint, LPVOID param) {
    if (!m_ProcessHandle || !fnNtCreateThreadEx) return NULL;

    if (entryPoint == 0) {
        if (m_EntryPoints.empty()) return NULL;

        size_t index = rand() % m_EntryPoints.size();
        entryPoint = m_EntryPoints[index];
    }

    HANDLE hThread = NULL;

    NTSTATUS status = fnNtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        m_ProcessHandle,
        (LPTHREAD_START_ROUTINE)entryPoint,
        param,
        0x00000004,
        0,
        0,
        0,
        NULL
    );

    if (NT_SUCCESS(status) && hThread) {
        std::lock_guard<std::mutex> lock(m_ThreadLock);
        m_ManagedThreads.push_back(hThread);

        HideThread(hThread);
        return hThread;
    }

    return NULL;
}

bool ThreadManager::ReviveThreads(bool forceNewThreads)
{
    bool createdAny = false;
    std::vector<HANDLE> deadThreads;
    bool needsConsoleThread = false;

    {
        std::lock_guard<std::mutex> lock(m_ThreadLock);

        for (auto it = m_ManagedThreads.begin(); it != m_ManagedThreads.end();) {
            HANDLE hThread = *it;
            DWORD exitCode = 0;

            if (!GetExitCodeThread(hThread, &exitCode) || exitCode != STILL_ACTIVE) {
                deadThreads.push_back(hThread);
                it = m_ManagedThreads.erase(it);
                fflush(stdout);
                needsConsoleThread = true;
            }
            else {
                if (fnNtGetContextThread && fnNtSetContextThread) {
                    CONTEXT ctx = { 0 };
                    ctx.ContextFlags = CONTEXT_CONTROL;

                    if (NT_SUCCESS(fnNtGetContextThread(hThread, &ctx))) {
                        if (ctx.Rip < m_DllBase || ctx.Rip >= m_DllBase + m_DllSize) {
                            for (const auto& entryPoint : m_EntryPoints) {
                                if (entryPoint != 0) {
                                    ctx.Rip = entryPoint;
                                    fnNtSetContextThread(hThread, &ctx);
                                    fflush(stdout);
                                    break;
                                }
                            }
                        }

                        DWORD suspendCount = SuspendThread(hThread);
                        if (suspendCount > 0) {
                            fflush(stdout);

                            while (suspendCount > 0) {
                                ResumeThread(hThread);
                                suspendCount--;
                            }
                            ResumeThread(hThread);
                        }
                        else {
                            ResumeThread(hThread);
                        }
                    }
                }
                ++it;
            }
        }
    }

    for (HANDLE hDeadThread : deadThreads) {
        CloseHandle(hDeadThread);

        HANDLE hNewThread = CreateHiddenThread();
        if (hNewThread) {
            createdAny = true;
            fflush(stdout);
        }
    }

    if (forceNewThreads || m_ManagedThreads.size() < 5 || needsConsoleThread) {
        for (int i = 0; i < 5 - m_ManagedThreads.size(); i++) {
            HANDLE hNewThread = CreateHiddenThread();
            if (hNewThread) {
                createdAny = true;
                fflush(stdout);
            }
        }

        if (needsConsoleThread) {
            HANDLE hConsoleThread = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
                ThreadManager* mgr = (ThreadManager*)param;

                while (true) {
                    fflush(stdout);

                    if (ferror(stdout)) {
                        clearerr(stdout);
                        freopen("CONOUT$", "w", stdout);
                        fflush(stdout);
                    }

                    Sleep(2000);
                }

                return 0;
                }, this, 0, nullptr);

            if (hConsoleThread) {
                fflush(stdout);
                CloseHandle(hConsoleThread);
            }
        }
    }

    return createdAny;
}

size_t ThreadManager::GetActiveThreadCount()
{
    std::lock_guard<std::mutex> lock(m_ThreadLock);
    return m_ManagedThreads.size();
}

std::vector<DWORD> ThreadManager::FindThreadsInDll()
{
    std::vector<DWORD> threadIds;
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetProcessId(m_ProcessHandle));

    if (hThreadSnap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te32 = { sizeof(THREADENTRY32) };

        if (Thread32First(hThreadSnap, &te32)) {
            do {
                if (te32.th32OwnerProcessID == GetProcessId(m_ProcessHandle)) {
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                    if (hThread) {
                        CONTEXT ctx = { 0 };
                        ctx.ContextFlags = CONTEXT_CONTROL;

                        if (GetThreadContext(hThread, &ctx)) {
                            if (ctx.Rip >= m_DllBase && ctx.Rip < m_DllBase + m_DllSize) {
                                threadIds.push_back(te32.th32ThreadID);
                            }
                        }
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hThreadSnap, &te32));
        }
        CloseHandle(hThreadSnap);
    }

    return threadIds;
}

void ThreadManager::CamouflageThreads()
{
    std::lock_guard<std::mutex> lock(m_ThreadLock);

    for (HANDLE hThread : m_ManagedThreads) {
        if (fnNtSetInformationThread) {
            uintptr_t fakeStartAddress = 0;

            HMODULE hMods[100];
            DWORD cbNeeded;
            if (EnumProcessModules(m_ProcessHandle, hMods, sizeof(hMods), &cbNeeded)) {
                for (unsigned i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                    MODULEINFO modInfo;
                    if (GetModuleInformation(m_ProcessHandle, hMods[i], &modInfo, sizeof(modInfo))) {
                        if ((uintptr_t)modInfo.lpBaseOfDll != m_DllBase) {
                            fakeStartAddress = (uintptr_t)modInfo.lpBaseOfDll + (rand() % (int)modInfo.SizeOfImage);
                            break;
                        }
                    }
                }
            }

            if (fakeStartAddress) {
                fnNtSetInformationThread(hThread, 9, &fakeStartAddress, sizeof(fakeStartAddress));
            }
        }

        if (fnNtGetContextThread && fnNtSetContextThread) {
            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_FULL;

            if (NT_SUCCESS(fnNtGetContextThread(hThread, &ctx))) {
                std::lock_guard<std::mutex> tlock(g_ThreadMutex);
                g_ThreadContexts[GetThreadId(hThread)] = ctx;

            }
        }
    }
}

void ThreadManager::RestoreThreadContexts()
{
    std::lock_guard<std::mutex> tlock(g_ThreadMutex);

    for (const auto& pair : g_ThreadContexts) {
        DWORD threadId = pair.first;
        const CONTEXT& savedCtx = pair.second;

        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
        if (hThread) {
            CONTEXT currentCtx = { 0 };
            currentCtx.ContextFlags = CONTEXT_CONTROL;

            if (GetThreadContext(hThread, &currentCtx)) {
                if (currentCtx.Rip < m_DllBase || currentCtx.Rip >= m_DllBase + m_DllSize) {
                    if (savedCtx.Rip >= m_DllBase && savedCtx.Rip < m_DllBase + m_DllSize) {
                        SuspendThread(hThread);

                        SetThreadContext(hThread, &savedCtx);

                        ResumeThread(hThread);
                        // threadId, savedCtx.Rip
                    }
                }
            }
            CloseHandle(hThread);
        }
    }
}