#pragma once
#define NOMINMAX
#include <Windows.h>
#include <string>
#include <map>
#include <cstdint>
#include <stdexcept>
#include <iostream>
#include <tlhelp32.h>
#include <thread>
#include <vector>
#include <filesystem>

#define Offset(Base, Length) reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(Base) + Length)

namespace Process {
    struct Module {
        uint32_t Size = 0;
        uintptr_t Start = 0;
        uintptr_t End = 0;
        HANDLE Target = INVALID_HANDLE_VALUE;
        std::string Name = "";
        std::map<std::string, void*> Exports = {};

        void* GetAddress(const std::string& Name);
    };

    struct Object {
        HANDLE _handle = INVALID_HANDLE_VALUE;
        uint32_t _id = 0;

        Module GetModule(const std::string& Name) const;
    };

    Object WaitForProcess(const std::wstring& Name);

    namespace details {
#pragma region Memory Utility
        template<typename T = void*, typename AddrType = void*>
        __forceinline T RemoteAlloc(HANDLE Handle, size_t Size = sizeof(T), uint32_t ProtectionType = PAGE_EXECUTE_READWRITE, uint32_t AllocationType = MEM_COMMIT | MEM_RESERVE) {
            void* Address = VirtualAllocEx(Handle, nullptr, Size, AllocationType, ProtectionType);

            if (!Address) {
                // VirtualAllocEx
            }

            return reinterpret_cast<T>(Address);
        }

        template<typename AddrType = void*>
        __forceinline void RemoteFree(HANDLE Handle, AddrType Address, size_t Size = 0, uint32_t FreeType = MEM_RELEASE) {
            bool Success = VirtualFreeEx(Handle, Address, Size, FreeType);
            if (!Success) {
                // VirtualFreeEx
            }
        }

        template<typename T = void*, typename AddrType = void*>
        __forceinline void RemoteWrite(HANDLE Handle, AddrType Address, T Buffer, size_t Size = sizeof(T)) {
            size_t Count = 0;
            bool Success = WriteProcessMemory(Handle, reinterpret_cast<void*>(Address), Buffer, Size, &Count);

            if (!Success) {
                // WriteProcessMemory
            }

            if (Count != Size) {
                // WriteProcessMemory Nawilobrivi
            }
        }

        template<typename AddrType = void*>
        __forceinline uint32_t RemoteProtect(HANDLE Handle, AddrType Address, size_t Size, uint32_t ProtectionType, bool* StatusOut = nullptr) {
            DWORD OriginalProtection = 0;
            bool Success = VirtualProtectEx(Handle, (void*)Address, Size, ProtectionType, &OriginalProtection);

            if (StatusOut) {
                *StatusOut = Success;
            }
            else if (!Success) {
                // VirtualAllocEx
            }

            return OriginalProtection;
        }

        template<typename T, typename AddrType = void*>
        __forceinline T RemoteRead(HANDLE Handle, AddrType Address, size_t Size = sizeof(T)) {
            void* Buffer = std::malloc(Size);

            if (!Buffer) {
                throw std::bad_alloc();
            }

            size_t Count = 0;
            bool Success = ReadProcessMemory(Handle, reinterpret_cast<void*>(Address), Buffer, Size, &Count);

            if (!Success) {
                // ReadProcessMemory
            }

            if (Count != Size) {
                // ReadProcessMemory Nawilobrivi
            }

            T Result = {};
            std::memcpy(&Result, Buffer, Size);
            std::free(Buffer);
            return Result;
        }

        template<typename T, typename AddrType = void*>
        __forceinline void RemoteRead(HANDLE Handle, AddrType Address, T* Buffer, size_t Size = sizeof(T)) {
            size_t Count = 0;
            bool Success = ReadProcessMemory(Handle, reinterpret_cast<void*>(Address), Buffer, Size, &Count);

            if (!Success) {
                // ReadProcessMemory
            }

            if (Count != Size) {
                // ReadProcessMemory Nawilobrivi
            }
        }

        template<typename AddrType = void*>
        __forceinline std::string ReadString(HANDLE Handle, AddrType Address, size_t Length = 0) {
            std::string Result = {};
            Result.resize(Length);

            uintptr_t Current = reinterpret_cast<uintptr_t>(Address);
            if (Length == 0) {
                char TempBuffer[16] = {};
                while (true) {
                    if (Result.size() > 10000) {
                        // ReadString Usasrulobis Albatoba
                    }

                    RemoteRead(Handle, Current, TempBuffer, sizeof(TempBuffer));
                    Current += sizeof(TempBuffer);

                    size_t Len = strnlen(TempBuffer, 16);
                    Result.append(TempBuffer, Len);

                    if (Len != 16) {
                        break;
                    }
                }
            }
            else {
                char* TempBuffer = new char[Length];
                RemoteRead(Handle, Current, TempBuffer, Length);
                Result.assign(TempBuffer, Length);
                delete[] TempBuffer;
            }

            return Result;
        }
#pragma endregion

#pragma region Process & Module Utility
        static HANDLE OpenSnapshot(uint32_t Flags, uint32_t Id, int maxRetries = 20) {
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

        static uint32_t _FindProcessByName(std::wstring Name) {
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

        static void UpdateExports(Module& Data) {
            void* Base = (void*)Data.Start;
            HANDLE Handle = Data.Target;

            if (Base == nullptr) {
                return;
            }

            IMAGE_DOS_HEADER DosHeader = details::RemoteRead<IMAGE_DOS_HEADER>(Handle, Base);

            if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
                return;
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

        static bool _FindModule(std::string Name, Module& Data, uint32_t Id, HANDLE Handle) {
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

        static uint32_t _WaitForProcess(std::wstring Name) {
            uint32_t ProcessId = 0;
            while (!ProcessId) {
                try {
                    ProcessId = _FindProcessByName(Name);
                }
                catch (const std::runtime_error& ex) {
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            return ProcessId;
        }
#pragma endregion
    }
}