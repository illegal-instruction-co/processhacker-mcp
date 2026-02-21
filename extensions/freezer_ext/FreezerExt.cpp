#include "../../include/McpExtensionApi.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include <windows.h>
#include <tlhelp32.h>

using nlohmann::json;

using namespace std;

bool SetProcessThreadsState(DWORD pid, bool suspend)
{
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnap, &te32)) {
        CloseHandle(hThreadSnap);
        return false;
    }

    bool success = false;
    do {
        if (te32.th32OwnerProcessID == pid) {
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
            if (hThread) {
                suspend ? SuspendThread(hThread) : ResumeThread(hThread);
                CloseHandle(hThread);
                success = true;
            }
        }
    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);
    return success;
}

const char* SuspendToolHandler(const char* jsonArgs)
{
    auto createResponse = [](const string& msg, bool isError = false) {
        json resp;
        resp["content"] = json::array({json{{"type", "text"}, {"text", msg}}});
        if (isError) resp["isError"] = true;
        string resStr = resp.dump();
#pragma warning(suppress : 28183)
        char* result = new char[resStr.size() + 1];
        strcpy_s(result, resStr.size() + 1, resStr.c_str());
        return result;
    };

    try {
        json j = json::parse(jsonArgs);
        auto pid = j.at("pid").get<DWORD>();
        string action = j.at("action").get<string>();

        if (action != "suspend" && action != "resume") {
            return createResponse("Error: invalid action (must be 'suspend' or 'resume')", true);
        }

        if (SetProcessThreadsState(pid, action == "suspend")) {
            return createResponse(string("Success: process threads ") + action + "ed");
        } else {
            return createResponse("Error: failed to interact with process threads", true);
        }

    } catch (const exception& e) {
        return createResponse(string("Error: ") + e.what(), true);
    }
}

void SuspendFreeResult(const char* resultStr)
{
    delete[] resultStr;
}

extern "C" __declspec(dllexport) bool InitMcpExtension(const McpServerApi* api)
{
    if (!api || !api->registerTool) {
        return false;
    }

    McpToolRegistration tool{};
    tool.name = "ext_process_freezer";
    tool.description = "Suspends or resumes all threads in a process (Time Stopper).";
    tool.version = "1.0.0";
    tool.inputSchemaJson = R"({
        "type": "object",
        "properties": {
            "pid": {"type": "integer", "description": "Process ID"},
            "action": {"type": "string", "description": "'suspend' to freeze, 'resume' to unfreeze"}
        },
        "required": ["pid", "action"]
    })";
    tool.handler = SuspendToolHandler;
    tool.freeResult = SuspendFreeResult;
    tool.isDestructive = true;

    api->registerTool(api->serverContext, &tool);
    return true;
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}
