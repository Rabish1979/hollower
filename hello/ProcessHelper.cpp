#include "ProcessHelper.h"
#include "ProcessInfo.h"
#include "CLogger.h"
#include "JsonCppWrapper.h"

extern CLogger g_Logger;

bool ProcessHelper::FetchProcessList(string &json)
{
    HANDLE hProcessSnap;
    HANDLE hProcess;
    PROCESSENTRY32 pe32;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        g_Logger.Log(L"CreateToolhelp32Snapshot of processes");
        return false;
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        printError(TEXT("Process32First")); // show cause of failure
        CloseHandle(hProcessSnap);          // clean the snapshot object
        return false;
    }

    do
    {
        _tprintf(TEXT("\nPROCESS NAME:  %s"), pe32.szExeFile);
        g_Logger.Log(pe32.szExeFile);

        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
        if (hProcess == NULL)
        {
            printError(TEXT("OpenProcess"));
            continue;
        }
        else
        {
            CloseHandle(hProcess);
        }

        ProcessInfo info;
        info.SetPath(pe32.szExeFile);
        info.SetProcessId(pe32.th32ProcessID);
        info.SetParentProcessId(pe32.th32ParentProcessID);

        // List the modules and threads associated with this process
        ListProcessModules(pe32.th32ProcessID, info.moduleList);
        info.threadList = ListProcessThreads(pe32.th32ProcessID);
        vProcInfo.push_back(info);

    } while (Process32Next(hProcessSnap, &pe32));

    JsonCppWrapper obj;
    json = obj.GetStringJsonObject(vProcInfo);

    CloseHandle(hProcessSnap);
    return true;
}


bool ProcessHelper::ListProcessModules(DWORD dwPID, vector<ModuleInfo> &moduleList)
{
    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
    MODULEENTRY32 me32;

    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
    if (hModuleSnap == INVALID_HANDLE_VALUE)
    {
        printError(TEXT("CreateToolhelp32Snapshot (of modules)"));
        return false;
    }

    me32.dwSize = sizeof(MODULEENTRY32);
    if (!Module32First(hModuleSnap, &me32))
    {
        printError(TEXT("Module32First"));
        CloseHandle(hModuleSnap);
        return false;
    }

    do
    {
        ModuleInfo objInfo;
        objInfo.name = me32.szModule;
        objInfo.path = me32.szExePath;
        moduleList.push_back(objInfo);

    } while (Module32Next(hModuleSnap, &me32));

    CloseHandle(hModuleSnap);
    return true;
}

vector<DWORD> ProcessHelper::ListProcessThreads(DWORD dwOwnerPID)
{
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
    THREADENTRY32 te32;
    vector<DWORD> moduleList;

    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
        return moduleList;

    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnap, &te32))
    {
        printError(TEXT("Thread32First"));
        CloseHandle(hThreadSnap);
        return moduleList;
    }

    do
    {
        if (te32.th32OwnerProcessID == dwOwnerPID)
        {
            _tprintf(TEXT("\n\n     THREAD ID      = 0x%08X"), te32.th32ThreadID);
            _tprintf(TEXT("\n     Base priority  = %d"), te32.tpBasePri);
            _tprintf(TEXT("\n     Delta priority = %d"), te32.tpDeltaPri);
            _tprintf(TEXT("\n"));
            moduleList.push_back(te32.th32ThreadID);
        }
    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);
    return moduleList;
}

void ProcessHelper::printError(TCHAR const* msg)
{
    DWORD eNum;
    TCHAR sysMsg[256];
    TCHAR* p;

    eNum = GetLastError();
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, eNum,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
        sysMsg, 256, NULL);

    // Trim the end of the line and terminate it with a null
    p = sysMsg;
    while ((*p > 31) || (*p == 9))
        ++p;
    do { *p-- = 0; } while ((p >= sysMsg) &&
        ((*p == '.') || (*p < 33)));

    // Display the message
    _tprintf(TEXT("\n  WARNING: %s failed with error %d (%s)"), msg, eNum, sysMsg);
}

