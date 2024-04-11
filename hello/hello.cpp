#include <windows.h>
#include "ProcessHelper.h"
#include "framework.h"
#include "CLogger.h"
#include "RestWrapper.h"

const wstring path = L"E:\\src\\hollowing\\hello";
volatile bool isContinue = true;
CLogger g_Logger;

void ThreadFunct() {
    while (isContinue) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10000));
        ProcessHelper obj; 
        string json;
        if (obj.FetchProcessList(json))
        {
            string host = "http://192.168.1.15:8080";
            RestWrapper::SendInfo(host, json);
            isContinue = true;
        }
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    g_Logger.Init(path);
    std::thread thread(ThreadFunct);
    thread.join();

    const std::string rawJson = R"({"Age": 20, "Name": "colin"})";
    const auto rawJsonLength = static_cast<int>(rawJson.length());
    constexpr bool shouldUseOldWay = false;
    JSONCPP_STRING err;
    Json::Value root;

    if (shouldUseOldWay) {
        Json::Reader reader;
        reader.parse(rawJson, root);
    }
    else
    {
        Json::CharReaderBuilder builder;
        const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
        if (!reader->parse(rawJson.c_str(), rawJson.c_str() + rawJsonLength, &root,
            &err)) {
            std::cout << "error" << std::endl;
            return EXIT_FAILURE;
        }
    }

    const std::string name = root["Name"].asString();
    const int age = root["Age"].asInt();

    std::cout << name << std::endl;
    std::cout << age << std::endl;

    /*{
        "action" : "run",
         "data" :
          {
            "number" : 1
          }
    }*/

    Json::Value root2;
    Json::Value data;
    root2["action"] = "run";
    data["number"] = 1;
    root2["data"] = data;

    if (shouldUseOldWay) {
        Json::FastWriter writer;
        const std::string json_file = writer.write(root2);
        std::cout << json_file << std::endl;
    }
    else {
        Json::StreamWriterBuilder builder;
        const std::string json_file = Json::writeString(builder, root2);
        std::cout << json_file << std::endl;
    }

	return 0;
}