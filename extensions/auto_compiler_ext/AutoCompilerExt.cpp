#include "../../include/McpExtensionApi.h"

#include <nlohmann/json.hpp>
#include <windows.h>

#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <iostream>

using nlohmann::json;
using namespace std;

const char* AutoCompilerHandler(const char* jsonArgs)
{
    auto createResponse = [](const string& msg, bool isError = false, const json& contentData = json::object()) {
        json resp;
        if (contentData.empty()) {
            resp["content"] = json::array({json{{"type", "text"}, {"text", msg}}});
        } else {
            resp["content"] = json::array({json{{"type", "text"}, {"text", contentData.dump(4)}}});
        }
        if (isError) resp["isError"] = true;
        string resStr = resp.dump();
#pragma warning(suppress : 28183)
        char* result = new char[resStr.size() + 1];
        strcpy_s(result, resStr.size() + 1, resStr.c_str());
        return result;
    };

    try {
        json payload = json::parse(jsonArgs);
        string extName = payload.at("extension_name").get<string>();
        string cCode = payload.at("c_code").get<string>();

        string workspaceDir = "extensions/dynamic_exts";
        CreateDirectoryA("extensions", NULL);
        CreateDirectoryA(workspaceDir.c_str(), NULL);
        
        string cPath = workspaceDir + "/" + extName + ".c";
        string dllPath = workspaceDir + "/" + extName + ".dll";

        ofstream outFile(cPath);
        if (!outFile) return createResponse("Error: Could not write C file to disk.", true);
        outFile << cCode;
        outFile.close();

        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        string exeDir = exePath;
        exeDir = exeDir.substr(0, exeDir.find_last_of("\\/"));
        string tccPath = exeDir + "\\tcc\\tcc.exe";

        ostringstream cmd;
        cmd << "\"" << tccPath << "\" -shared -o " << extName << ".dll " << extName << ".c";

        SECURITY_ATTRIBUTES saAttr; 
        saAttr.nLength = sizeof(SECURITY_ATTRIBUTES); 
        saAttr.bInheritHandle = TRUE; 
        saAttr.lpSecurityDescriptor = NULL; 

        HANDLE hChildStd_OUT_Rd = NULL;
        HANDLE hChildStd_OUT_Wr = NULL;

        if (!CreatePipe(&hChildStd_OUT_Rd, &hChildStd_OUT_Wr, &saAttr, 0)) {
            return createResponse("Error: CreatePipe failed.", true);
        }
        if (!SetHandleInformation(hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0)) {
            return createResponse("Error: Stdout SetHandleInformation failed.", true);
        }

        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.hStdError = hChildStd_OUT_Wr;
        si.hStdOutput = hChildStd_OUT_Wr;
        si.dwFlags |= STARTF_USESTDHANDLES;
        ZeroMemory(&pi, sizeof(pi));

        string cmdStr = cmd.str();
        vector<char> cmdBuffer(cmdStr.begin(), cmdStr.end());
        cmdBuffer.push_back('\0');

        if (!CreateProcessA(NULL, cmdBuffer.data(), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, workspaceDir.c_str(), &si, &pi)) {
            CloseHandle(hChildStd_OUT_Wr);
            CloseHandle(hChildStd_OUT_Rd);
            return createResponse("Error: Failed to launch TCC Compiler.", true);
        }

        CloseHandle(hChildStd_OUT_Wr);

        string compilerOutput = "";
        DWORD dwRead; 
        CHAR chBuf[4096]; 
        BOOL bSuccess = FALSE;
        for (;;) { 
            bSuccess = ReadFile(hChildStd_OUT_Rd, chBuf, 4096 - 1, &dwRead, NULL);
            if (!bSuccess || dwRead == 0) break; 
            chBuf[dwRead] = '\0';
            compilerOutput += chBuf;
        } 
        CloseHandle(hChildStd_OUT_Rd);

        WaitForSingleObject(pi.hProcess, 15000);

        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        if (exitCode != 0) {
            string errMessage = "Error: Compilation failed. TCC Output:\n" + compilerOutput;
            return createResponse(errMessage, true);
        }

        HMODULE hModule = LoadLibraryA(dllPath.c_str());
        if (!hModule) {
            return createResponse("Error: Compiled dynamically but LoadLibraryA failed. Code: " + to_string(GetLastError()), true);
        }

        using InitMcpExtFn = bool(*)(const McpServerApi*);
        auto initFn = reinterpret_cast<InitMcpExtFn>(GetProcAddress(hModule, "InitMcpExtension"));
        
        if (!initFn) {
            return createResponse("Error: Library loaded but missing InitMcpExtension export.", true);
        }

        return createResponse("", false, json::object({
            {"status", "success"},
            {"message", "Extension compiled with TCC and hot-loaded into active memory!"},
            {"dll_path", dllPath}
        }));

    } catch (const exception& e) {
        return createResponse(string("Error: ") + e.what(), true);
    }
}

void AutoCompilerFreeResult(const char* resultStr)
{
    delete[] resultStr;
}

extern "C" __declspec(dllexport) bool InitMcpExtension(const McpServerApi* api)
{
    if (!api || !api->registerTool) {
        return false;
    }

    McpToolRegistration tReg{};
    tReg.name = "ext_auto_compiler";
    tReg.description = "DANGEROUS: Core capability to allow the AI to compile raw C code into a self-loading Extension DLL dynamically. DO NOT RUN WITHOUT EXPLICIT USER CONSENT.";
    tReg.version = "1.0.0";
    tReg.inputSchemaJson = "{\"type\":\"object\",\"properties\":{\"extension_name\":{\"type\":\"string\",\"description\":\"Unique short name without .dll\"},\"c_code\":{\"type\":\"string\",\"description\":\"Full C source code adhering to McpExtensionApi.h template\"}},\"required\":[\"extension_name\",\"c_code\"]}";
    tReg.handler = AutoCompilerHandler;
    tReg.freeResult = AutoCompilerFreeResult;

    api->registerTool(api->serverContext, &tReg);
    return true;
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}
