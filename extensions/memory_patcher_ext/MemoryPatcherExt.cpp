#include "../../include/McpExtensionApi.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <iomanip>

#include <windows.h>

using nlohmann::json;
using namespace std;

const char* MemoryPatcherHandler(const char* jsonArgs)
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
        json j = json::parse(jsonArgs);
        auto pid = j.at("pid").get<DWORD>();
        string addrStr = j.at("address").get<string>();
        string hexStr = j.at("hex_bytes").get<string>();

        auto parseAddress = [](const string& addr) -> uintptr_t {
            uintptr_t result = 0;
            istringstream iss(addr);
            if (addr.find("0x") == 0 || addr.find("0X") == 0) {
                iss >> hex >> result;
            } else {
                iss >> result;
            }
            return result;
        };

        auto parseHexBytes = [](const string& hexData) -> vector<uint8_t> {
            vector<uint8_t> bytes;
            string cleanHex = hexData;
            cleanHex.erase(remove_if(cleanHex.begin(), cleanHex.end(), ::isspace), cleanHex.end());

            for (size_t i = 0; i < cleanHex.length(); i += 2) {
                string byteString = cleanHex.substr(i, 2);
                uint8_t byte = static_cast<uint8_t>(stoul(byteString, nullptr, 16));
                bytes.push_back(byte);
            }
            return bytes;
        };

        uintptr_t targetAddress = parseAddress(addrStr);
        if (targetAddress == 0) return createResponse("Error: Invalid address format", true);

        vector<uint8_t> patchBytes = parseHexBytes(hexStr);
        if (patchBytes.empty()) return createResponse("Error: Empty or invalid hex_bytes", true);

        HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
        if (!hProcess) return createResponse("Error: Cannot open process for writing. Ensure it's not protected by Anti-Cheat or run as Admin.", true);

        auto cleanup = [&]() { CloseHandle(hProcess); };

        DWORD oldProtect;
        if (!VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(targetAddress), patchBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            cleanup();
            return createResponse("Error: VirtualProtectEx failed. OS blocked protection change.", true);
        }

        SIZE_T bytesWritten = 0;
        bool writeSuccess = WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(targetAddress), patchBytes.data(), patchBytes.size(), &bytesWritten);

        DWORD tempProtect;
        VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(targetAddress), patchBytes.size(), oldProtect, &tempProtect);

        if (!writeSuccess || bytesWritten != patchBytes.size()) {
            cleanup();
            return createResponse("Error: WriteProcessMemory failed or incomplete write.", true);
        }

        cleanup();

        json results = json::object();
        results["status"] = "success";
        results["bytes_written"] = bytesWritten;
        results["patched_address"] = (ostringstream() << hex << "0x" << targetAddress).str();

        return createResponse("", false, results);

    } catch (const exception& e) {
        return createResponse(string("Error: ") + e.what(), true);
    }
}

void MemoryPatcherFreeResult(const char* resultStr)
{
    delete[] resultStr;
}

extern "C" __declspec(dllexport) bool InitMcpExtension(const McpServerApi* api)
{
    if (!api || !api->registerTool) {
        return false;
    }

    McpToolRegistration tReg{};
    tReg.name = "ext_memory_patcher";
    tReg.description = "Writes arbitrary hex bytes to a specified memory address in a target process.";
    tReg.version = "1.0.0";
    tReg.inputSchemaJson = "{\"type\":\"object\",\"properties\":{\"pid\":{\"type\":\"integer\",\"description\":\"Target Process ID\"},\"address\":{\"type\":\"string\",\"description\":\"Memory address\"},\"hex_bytes\":{\"type\":\"string\",\"description\":\"Bytes to write\"}},\"required\":[\"pid\",\"address\",\"hex_bytes\"]}";
    tReg.handler = MemoryPatcherHandler;
    tReg.freeResult = MemoryPatcherFreeResult;

    api->registerTool(api->serverContext, &tReg);
    return true;
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}
