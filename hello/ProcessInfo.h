#pragma once
#include "framework.h"
#include "ModuleInfo.h"

class ProcessInfo
{
public:
    ProcessInfo():processid(0), parentProcessID(0), strpath(L"")
    {
    }

private:
    wstring strpath;
    DWORD processid;
    DWORD parentProcessID;

public:
    vector<ModuleInfo> moduleList;
    vector<DWORD> threadList;
public:
    void SetPath(wstring path)
    {
        strpath = path;
    }

    void SetProcessId(DWORD id)
    {
        processid = id;
    }

    void SetParentProcessId(DWORD id)
    {
        parentProcessID = id;
    }

    void AddModulePath(ModuleInfo info)
    {
        moduleList.push_back(info);
    }

    void AddThreadToList(DWORD threadId)
    {
        threadList.push_back(threadId);
    }

    wstring& GetProcessPath()
    {
        return strpath;
    }

    INT GetProcessID()
    {
        return processid;
    }

    DWORD GetParentProcessID()
    {
        return parentProcessID;
    }

    vector<ModuleInfo>& GetModuleList()
    {
        return moduleList;
    }
};

