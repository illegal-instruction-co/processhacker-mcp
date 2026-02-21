#include "../../include/McpExtensionApi.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <windows.h>
#include <psapi.h>

using nlohmann::json;

using namespace std;

struct PatternByte {
    uint8_t value;
    bool isWildcard;
};

vector<PatternByte> ParsePattern(const string& signature)
{
    vector<PatternByte> patternBytes;
    istringstream iss(signature);
    string token;

    auto pushWildcard = [&]() { patternBytes.push_back({0, true}); };
    auto pushByte = [&](const string& t) { 
        patternBytes.push_back({static_cast<uint8_t>(strtoul(t.c_str(), nullptr, 16)), false}); 
    };

    while (iss >> token) {
        (token == "?" || token == "??") ? pushWildcard() : pushByte(token);
    }
    return patternBytes;
}

size_t FindPatternInBuffer(const vector<uint8_t>& buffer, const vector<PatternByte>& pattern)
{
    if (pattern.size() > buffer.size() || pattern.empty()) {
        return static_cast<size_t>(-1);
    }

    auto matcher = [](uint8_t memByte, const PatternByte& pb) {
        return pb.isWildcard || memByte == pb.value;
    };

    auto it = search(buffer.begin(), buffer.end(), pattern.begin(), pattern.end(), matcher);
    return (it != buffer.end()) ? distance(buffer.begin(), it) : static_cast<size_t>(-1);
}

const char* PatternScannerToolHandler(const char* jsonArgs)
{
    auto createErrorResponse = [](const exception& e) {
        json errBlock = { {"type", "text"}, {"text", string("Error: ") + e.what()} };
        json errResp;
        errResp["content"] = json::array({errBlock});
        errResp["isError"] = true;
        string resStr = errResp.dump();
#pragma warning(suppress : 28183)
        char* result = new char[resStr.size() + 1];
        strcpy_s(result, resStr.size() + 1, resStr.c_str());
        return result;
    };

    try {
        json j = json::parse(jsonArgs);
        auto pid = j.at("pid").get<DWORD>();
        string patternStr = j.at("pattern").get<string>();
        string moduleName = j.value("module", "");

        auto pattern = ParsePattern(patternStr);
        if (pattern.empty()) {
            throw runtime_error("Invalid pattern format");
        }

        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProcess) {
            throw runtime_error("Failed to open process");
        }

        uintptr_t searchStart = 0;
        uintptr_t searchEnd = 0x7FFFFFFFFFFF;

        auto resolveModuleBounds = [&]() {
            if (moduleName.empty()) return true;
            HMODULE hMods[1024];
            DWORD cbNeeded;
            if (!EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) return false;

            size_t numModules = cbNeeded / sizeof(HMODULE);
            vector<HMODULE> modsVec(hMods, hMods + numModules);

            auto it = find_if(modsVec.begin(), modsVec.end(), [&](HMODULE hMod) {
                char szModName[MAX_PATH];
                return GetModuleBaseNameA(hProcess, hMod, szModName, sizeof(szModName)) && (moduleName == szModName);
            });

            if (it != modsVec.end()) {
                MODULEINFO modInfo;
                if (GetModuleInformation(hProcess, *it, &modInfo, sizeof(modInfo))) {
                    searchStart = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
                    searchEnd = searchStart + modInfo.SizeOfImage;
                    return true;
                }
            }
            return false;
        };

        if (!resolveModuleBounds()) {
            CloseHandle(hProcess);
            throw runtime_error("Module not found: " + moduleName);
        }

        uintptr_t currentAddr = searchStart;
        vector<uintptr_t> foundAddresses;

        auto extractPatternMatches = [&](const vector<uint8_t>& buffer, size_t bytesRead, uintptr_t baseAddr) {
            size_t offset = 0;
            auto scanNext = [&]() -> bool {
                if (offset >= buffer.size()) return false;
                vector<uint8_t> subBuffer(buffer.begin() + offset, buffer.end());
                size_t match = FindPatternInBuffer(subBuffer, pattern);
                if (match != static_cast<size_t>(-1)) {
                    foundAddresses.push_back(baseAddr + offset + match);
                    offset += match + 1;
                    return foundAddresses.size() < 50;
                }
                return false;
            };
            while (scanNext());
        };

        auto processMemoryRegion = [&]() -> bool {
            MEMORY_BASIC_INFORMATION mbi;
            if (!VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(currentAddr), &mbi, sizeof(mbi))) return false;

            bool isCommit = (mbi.State == MEM_COMMIT);
            bool isReadable = (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));
            
            if (isCommit && isReadable) {
                size_t regionSize = mbi.RegionSize;
                if (currentAddr + regionSize > searchEnd && searchEnd != 0x7FFFFFFFFFFF) {
                    regionSize = searchEnd - currentAddr;
                }

                vector<uint8_t> buffer(regionSize);
                SIZE_T bytesRead;
                if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(currentAddr), buffer.data(), regionSize, &bytesRead)) {
                    buffer.resize(bytesRead);
                    extractPatternMatches(buffer, bytesRead, currentAddr);
                }
            }
            currentAddr += mbi.RegionSize;
            return foundAddresses.size() < 50 && currentAddr < searchEnd;
        };

        while (processMemoryRegion());

        CloseHandle(hProcess);

        json resultObj = json::object();
        json addresses = json::array();
        
        for_each(foundAddresses.begin(), foundAddresses.end(), [&addresses](uintptr_t addr) {
            stringstream ss;
            ss << "0x" << hex << uppercase << addr;
            addresses.push_back(ss.str());
        });

        resultObj["found_count"] = foundAddresses.size();
        resultObj["addresses"] = addresses;
        
        json responseObj;
        responseObj["content"] = json::array({json{{"type", "text"}, {"text", resultObj.dump(4)}}});

        string resStr = responseObj.dump();
#pragma warning(suppress : 28183)
        char* result = new char[resStr.size() + 1];
        strcpy_s(result, resStr.size() + 1, resStr.c_str());
        return result;

    } catch (const exception& e) {
        return createErrorResponse(e);
    }
}

void PatternScannerFreeResult(const char* resultStr)
{
    delete[] resultStr;
}

extern "C" __declspec(dllexport) bool InitMcpExtension(const McpServerApi* api)
{
    if (!api || !api->registerTool) {
        return false;
    }

    McpToolRegistration tool{};
    tool.name = "ext_pattern_scanner";
    tool.description = "Scans process memory for a byte signature/pattern. Bypasses static offsets.";
    tool.version = "1.0.0";
    tool.inputSchemaJson = R"({
        "type": "object",
        "properties": {
            "pid": {"type": "integer", "description": "Process ID"},
            "pattern": {"type": "string", "description": "Byte pattern e.g. '48 8B 05 ? ? ? ? 48 85 C0'"},
            "module": {"type": "string", "description": "Optional: Only scan specific module e.g. 'client.dll'"}
        },
        "required": ["pid", "pattern"]
    })";
    tool.handler = PatternScannerToolHandler;
    tool.freeResult = PatternScannerFreeResult;
    tool.isDestructive = false;

    api->registerTool(api->serverContext, &tool);
    return true;
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}
