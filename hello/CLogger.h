#pragma once
#include "framework.h"

class CLogger
{
private:
    wstring m_filePath;
    wofstream m_ofs;
public:
    ~CLogger()
    {
        if (m_ofs.is_open())
        {
            m_ofs.close();
        }
    }

    void Init(wstring path)
    {
        m_filePath = path + L"\\log_" + getCurrentDateTime("date") + L".txt";
        m_ofs.open(m_filePath.c_str(), std::ios_base::out | std::ios_base::app);
    }

    wstring getCurrentDateTime(string s) {
        time_t now = time(0);
        struct tm  tstruct;
        wchar_t  buf[80];
        tstruct = *localtime(&now);
        if (s == "now")
            wcsftime(buf, sizeof(buf), L"%Y-%m-%d %X", &tstruct);
        else if (s == "date")
            wcsftime(buf, sizeof(buf), L"%Y-%m-%d", &tstruct);

        return wstring(buf);
    };

    void Log(wstring logMsg) {
        if (!m_ofs.is_open())
            return;
        wstring now = getCurrentDateTime("now");   
        m_ofs << now << '\t' << logMsg << '\n';
        m_ofs.flush();
    }
};

