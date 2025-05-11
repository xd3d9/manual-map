#include "process.h"
#include <filesystem>
#include <tlhelp32.h>

namespace Process {
    Module Object::GetModule(const std::string& Name) const {
        return details::_WaitForModule(Name, _id, _handle);
    }

    Object WaitForProcess(const std::wstring& Name) {
        uint32_t Id = details::_WaitForProcess(Name);
        HANDLE Handle = OpenProcess(PROCESS_ALL_ACCESS, false, Id);

        if (!Handle) {
            //
        }

        return { Handle, Id };
    }

    namespace details {
        HANDLE OpenSnapshot(uint32_t Flags, uint32_t Id, int maxRetries) {
            HANDLE Snapshot = CreateToolhelp32Snapshot(Flags, Id);
            int retryCount = 0;

            while (Snapshot == INVALID_HANDLE_VALUE) {
                DWORD lastError = GetLastError();
                if (lastError == ERROR_ACCESS_DENIED || lastError == ERROR_INVALID_PARAMETER) {
                    return INVALID_HANDLE_VALUE;
                }

                if (lastError == ERROR_BAD_LENGTH && Flags == TH32CS_SNAPMODULE || Flags == TH32CS_SNAPMODULE32) {
                    Snapshot = CreateToolhelp32Snapshot(Flags, Id);
                    continue;
                }

                if (++retryCount >= maxRetries) {
                    return INVALID_HANDLE_VALUE;
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                Snapshot = CreateToolhelp32Snapshot(Flags, Id);
            }

            return Snapshot;
        }

        uint32_t _FindProcessByName(std::wstring Name) {
            uint32_t HighestCount = 0;
            uint32_t ProcessId = 0;

            HANDLE Snapshot = OpenSnapshot(TH32CS_SNAPPROCESS, 0);

            PROCESSENTRY32W Entry = {};
            Entry.dwSize = sizeof(Entry);

            if (!Process32First(Snapshot, &Entry)) {
                CloseHandle(Snapshot);
            }

            do {
                if (Name == std::wstring(Entry.szExeFile) && Entry.cntThreads > HighestCount) {
                    HighestCount = Entry.cntThreads;
                    ProcessId = Entry.th32ProcessID;
                }
            } while (Process32Next(Snapshot, &Entry));

            CloseHandle(Snapshot);
            return ProcessId;
        }

        bool _FindModule(std::string Name, Module& Data, uint32_t Id, HANDLE Handle) {
            HANDLE Snapshot = OpenSnapshot(TH32CS_SNAPMODULE, Id);

            MODULEENTRY32 Entry = {};
            Entry.dwSize = sizeof(Entry);

            if (!Module32First(Snapshot, &Entry)) {
                CloseHandle(Snapshot);
                
            }

            do {
                if (Entry.th32ProcessID != Id) {
                    continue;
                }

                std::filesystem::path Path(Entry.szExePath);

                if (Name == Path.filename().string()) {
                    Data.Name = Name;
                    Data.Size = Entry.modBaseSize;
                    Data.Target = Handle;
                    Data.Start = reinterpret_cast<uintptr_t>(Entry.modBaseAddr);
                    Data.End = Data.Start + Data.Size;
                    UpdateExports(Data);
                    CloseHandle(Snapshot);
                    return true;
                }
            } while (Module32Next(Snapshot, &Entry));

            CloseHandle(Snapshot);
            return false;
        }

        Module _WaitForModule(std::string Name, uint32_t Id, HANDLE Handle) {
            Module Data = {};

            while (!_FindModule(Name, Data, Id, Handle)) {}

            return Data;
        }

        uint32_t _WaitForProcess(std::wstring Name) {
            uint32_t ProcessId = 0;
            while (!ProcessId) {
                try {
                    ProcessId = _FindProcessByName(Name);
                }
                catch (const std::runtime_error& ex) {
                    //
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            return ProcessId;
        }

        void UpdateExports(Module& Data) {
            void* Base = (void*)Data.Start;
            HANDLE Handle = Data.Target;

            if (Base == nullptr) {
                return;
            }

            IMAGE_DOS_HEADER DosHeader = details::RemoteRead<IMAGE_DOS_HEADER>(Handle, Base);

            if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
                //
            }

            IMAGE_NT_HEADERS64 NtHeaders = RemoteRead<IMAGE_NT_HEADERS64>(Handle, Offset(Base, DosHeader.e_lfanew));
            IMAGE_DATA_DIRECTORY ExportDataDirectory = NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (!ExportDataDirectory.VirtualAddress) {
                return;
            }
            if (!ExportDataDirectory.Size) {
                return;
            }
            IMAGE_EXPORT_DIRECTORY ExportDirectory = RemoteRead<IMAGE_EXPORT_DIRECTORY>(Handle, Offset(Base, ExportDataDirectory.VirtualAddress));

            DWORD NumberOfNames = ExportDirectory.NumberOfNames;
            DWORD NumberOfFunctions = ExportDirectory.NumberOfFunctions;

            void* AddressOfFunctions = Offset(Base, ExportDirectory.AddressOfFunctions);
            void* AddressOfNames = Offset(Base, ExportDirectory.AddressOfNames);
            void* AddressOfNameOrdinals = Offset(Base, ExportDirectory.AddressOfNameOrdinals);

            std::vector<DWORD> NameRVAs = {};
            NameRVAs.resize(NumberOfNames);
            RemoteRead<DWORD>(Handle, AddressOfNames, NameRVAs.data(), NumberOfNames * sizeof(DWORD));

            std::vector<WORD> OrdinalsRVAs = {};
            OrdinalsRVAs.resize(NumberOfNames);
            RemoteRead<WORD>(Handle, AddressOfNameOrdinals, OrdinalsRVAs.data(), NumberOfNames * sizeof(WORD));

            std::vector<DWORD> FunctionRVAs = {};
            FunctionRVAs.resize(NumberOfFunctions);
            RemoteRead<DWORD>(Handle, AddressOfFunctions, FunctionRVAs.data(), NumberOfFunctions * sizeof(DWORD));

            size_t Index = 0;
            for (DWORD NameRVA : NameRVAs) {
                std::string NameString = ReadString(Handle, Offset(Base, NameRVA));
                WORD NameOrdinal = OrdinalsRVAs[Index];
                Data.Exports[NameString] = Offset(Base, FunctionRVAs[NameOrdinal]);
                Index++;
            }
        };
    }
}