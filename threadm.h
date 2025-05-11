#pragma once
#define NOMINMAX
#include <Windows.h>
#include <vector>
#include <mutex>
#include <unordered_map>

std::unordered_map<DWORD, CONTEXT> g_ThreadContexts;
std::mutex g_ThreadMutex;

class ThreadManager {
private:
    HANDLE m_ProcessHandle;
    uintptr_t m_DllBase;
    size_t m_DllSize;
    std::vector<HANDLE> m_ManagedThreads;
    std::vector<uintptr_t> m_EntryPoints;
    std::mutex m_ThreadLock;

    // Funqciis Pointerebi
    typedef NTSTATUS(NTAPI* pNtSetInformationThread)(HANDLE, ULONG, PVOID, ULONG);
    typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, LPVOID);
    typedef NTSTATUS(NTAPI* pNtSetContextThread)(HANDLE, PCONTEXT);
    typedef NTSTATUS(NTAPI* pNtGetContextThread)(HANDLE, PCONTEXT);

    pNtSetInformationThread fnNtSetInformationThread;
    pNtCreateThreadEx fnNtCreateThreadEx;
    pNtSetContextThread fnNtSetContextThread;
    pNtGetContextThread fnNtGetContextThread;

public:
    ThreadManager(HANDLE hProcess, uintptr_t dllBase, size_t dllSize);
    ~ThreadManager();

    void FindEntryPoints();
    bool HideThread(HANDLE hThread);
    HANDLE CreateHiddenThread(uintptr_t entryPoint = 0, LPVOID param = NULL);
    bool ReviveThreads(bool forceNewThreads = false);
    size_t GetActiveThreadCount();
    std::vector<DWORD> FindThreadsInDll();
    void CamouflageThreads();
    void RestoreThreadContexts();
};