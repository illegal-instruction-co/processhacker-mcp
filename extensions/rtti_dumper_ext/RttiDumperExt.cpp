#include "../../include/McpExtensionApi.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include <windows.h>
#include <psapi.h>

using nlohmann::json;

using namespace std;

struct RTTICompleteObjectLocator {
    DWORD signature;
    DWORD offset;
    DWORD cdOffset;
    DWORD pTypeDescriptor;
    DWORD pClassDescriptor;
    DWORD pSelf;
};

const char* RttiToolHandler(const char* jsonArgs)
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
        string moduleName = j.value("module", "");

        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProcess) return createResponse("Error: cannot open process", true);

        auto cleanup = [&]() { CloseHandle(hProcess); };

        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (!EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
            cleanup();
            return createResponse("Error: cannot enumerate modules", true);
        }

        uintptr_t targetModuleBase = 0;
        DWORD targetModuleSize = 0;

        auto findModule = [&]() {
            vector<HMODULE> modules(hMods, hMods + (cbNeeded / sizeof(HMODULE)));
            for (auto hMod : modules) {
                char szModName[MAX_PATH];
                if (GetModuleBaseNameA(hProcess, hMod, szModName, sizeof(szModName))) {
                    if (moduleName.empty() || _stricmp(szModName, moduleName.c_str()) == 0) {
                        MODULEINFO modInfo;
                        if (GetModuleInformation(hProcess, hMod, &modInfo, sizeof(modInfo))) {
                            targetModuleBase = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
                            targetModuleSize = modInfo.SizeOfImage;
                            return true;
                        }
                    }
                }
            }
            return false;
        };

        if (!findModule()) {
            cleanup();
            return createResponse("Error: target module not found", true);
        }

        vector<uint8_t> moduleMemory(targetModuleSize);
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(targetModuleBase), moduleMemory.data(), targetModuleSize, &bytesRead) || bytesRead == 0) {
            cleanup();
            return createResponse("Error: cannot read module memory", true);
        }

        IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(moduleMemory.data());
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            cleanup();
            return createResponse("Error: invalid DOS signature", true);
        }

        IMAGE_NT_HEADERS64* pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(moduleMemory.data() + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
            cleanup();
            return createResponse("Error: invalid NT signature", true);
        }

        IMAGE_SECTION_HEADER* pSection = IMAGE_FIRST_SECTION(pNtHeaders);
        uintptr_t rdataStart = 0;
        DWORD rdataSize = 0;

        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSection++) {
            if (strncmp(reinterpret_cast<const char*>(pSection->Name), ".rdata", 6) == 0) {
                rdataStart = pSection->VirtualAddress;
                rdataSize = pSection->Misc.VirtualSize;
                break;
            }
        }

        if (rdataStart == 0) {
            cleanup();
            return createResponse("Error: .rdata section not found", true);
        }

        json results = json::object();
        results["found_classes"] = json::array();

        auto parseRtti = [&]() {
            auto processLocator = [&](DWORD offset) {
                RTTICompleteObjectLocator* pLocator = reinterpret_cast<RTTICompleteObjectLocator*>(moduleMemory.data() + offset);
                if (pLocator->signature != 1 || pLocator->pSelf != offset) return;
                
                uintptr_t typeDescOffset = pLocator->pTypeDescriptor;
                if (typeDescOffset <= rdataStart || typeDescOffset >= (rdataStart + rdataSize)) return;
                
                uintptr_t nameOffset = typeDescOffset + 16; 
                if (nameOffset >= targetModuleSize) return;

                string className = reinterpret_cast<const char*>(moduleMemory.data() + nameOffset);
                if (className.length() <= 2 || className.substr(0, 2) != ".?") return;

                json classInfo;
                classInfo["name"] = className;
                classInfo["rva_locator"] = offset;
                classInfo["address_locator"] = (ostringstream() << hex << "0x" << (targetModuleBase + offset)).str();
                results["found_classes"].push_back(classInfo);
            };

            for (DWORD offset = rdataStart; offset < rdataStart + rdataSize - sizeof(RTTICompleteObjectLocator); offset += 4) {
                processLocator(offset);
            }
        };

        parseRtti();
        cleanup();

        results["status"] = "success";
        results["module"] = moduleName.empty() ? "main_module" : moduleName;
        results["base_address"] = (ostringstream() << hex << "0x" << targetModuleBase).str();
        results["total_found"] = results["found_classes"].size();

        return createResponse("", false, results);

    } catch (const exception& e) {
        return createResponse(string("Error: ") + e.what(), true);
    }
}

void RttiFreeResult(const char* resultStr)
{
    delete[] resultStr;
}

extern "C" __declspec(dllexport) bool InitMcpExtension(const McpServerApi* api)
{
    if (!api || !api->registerTool) {
        return false;
    }

    McpToolRegistration tReg{};
    tReg.name = "ext_rtti_dumper";
    tReg.description = "Scans memory for exactly x64 MSVC RTTI locators and dumps Class Names (Reverse Engineering).";
    tReg.version = "1.0.0";
    tReg.inputSchemaJson = "{\"type\":\"object\",\"properties\":{\"pid\":{\"type\":\"integer\",\"description\":\"Process ID\"},\"module\":{\"type\":\"string\",\"description\":\"Optional module name\"}},\"required\":[\"pid\"]}";
    tReg.handler = RttiToolHandler;
    tReg.freeResult = RttiFreeResult;

    api->registerTool(api->serverContext, &tReg);
    return true;
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}
