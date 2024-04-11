#pragma once
#include "json/json.h"
#include "ProcessInfo.h"

extern CLogger g_Logger;;
class JsonCppWrapper
{
public:
    string GetStringJsonObject(vector<ProcessInfo> vProcInfo)
    {
        vector<ProcessInfo>::iterator itr;
        Json::Value root;

        int i = 0;
        for(itr = vProcInfo.begin(); itr != vProcInfo.end(); itr++)
        {
            char buffer[20];
            memset(buffer, 0, sizeof(buffer));
            Json::Value obj;
            std::string s(itr->GetProcessPath().begin(), itr->GetProcessPath().end());

            obj["ID"] = _itoa(itr->GetProcessID(), buffer, 10);
            obj["Path"] = s;
            memset(buffer, 0, sizeof(buffer));
            obj["ParentID"] = _itoa(itr->GetParentProcessID(), buffer, 10);

            Json::Value moduleList;
            Json::Value module;

            vector<ModuleInfo>::iterator itrModule;
            for (itrModule = itr->GetModuleList().begin(); itrModule != itr->GetModuleList().end(); itrModule++)
            {
                std::string name(itrModule->name.begin(), itrModule->name.end());
                std::string path(itrModule->path.begin(), itrModule->path.end());
                module["Name"] = name;
                module["Path"] = path;
                moduleList.append(module);
            }

            obj["ModuleList"] = moduleList;
            root.append(obj);
        }

        Json::FastWriter writer;
        std::string json = writer.write(root);
        return json;
    }
};

