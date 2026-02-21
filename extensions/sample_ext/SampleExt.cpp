#include "../../include/McpExtensionApi.h"

#include <iostream>
#include <string>

#include <windows.h>

using namespace std;

const char* SampleMemoryToolHandler(const char* jsonArgs)
{
	string response = R"({
        "content": [{
            "type": "text",
            "text": "[SampleExt] Read 8 bytes (Mocked Direct Syscall): 48 89 5C 24 08"
        }]
    })";

	char* result = new char[response.size() + 1];
	strcpy_s(result, response.size() + 1, response.c_str());
	return result;
}

void SampleFreeResult(const char* resultStr)
{
	delete[] resultStr;
}

extern "C" __declspec(dllexport) bool InitMcpExtension(const McpServerApi* api)
{
	if (!api || !api->registerTool) {
		return false;
	}

	cerr << "[SampleExt] Initializing direct syscall extension...\n";

	McpToolRegistration tool{};
	tool.name = "ext_sample_read_memory_syscall";
	tool.description = "Reads memory using direct assembly syscalls, bypassing ntdll.dll user-mode hooks.";
	tool.version = "1.0.0";
	tool.inputSchemaJson = R"({
        "type": "object",
        "properties": {
            "pid": {"type": "integer", "description": "Process ID"},
            "address": {"type": "string", "description": "Target hex address"}
        },
        "required": ["pid", "address"]
    })";
	tool.handler = SampleMemoryToolHandler;
	tool.freeResult = SampleFreeResult;
	tool.isDestructive = false;

	api->registerTool(api->serverContext, &tool);

	return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	return TRUE;
}
