#pragma once

#include "ProcessInfo.h"
using namespace std;

class ProcessHelper
{
private:
	vector<ProcessInfo> vProcInfo;
public:
	bool FetchProcessList(string &json);

private:
	bool ListProcessModules(DWORD dwPID, vector<ModuleInfo> &moduleList);
	vector<DWORD> ListProcessThreads(DWORD dwOwnerPID);
	void printError(TCHAR const* msg);
};
