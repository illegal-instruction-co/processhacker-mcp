#include "../../include/McpExtensionApi.h"
#include "VehButNot.h"

#include <format>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>

using namespace std;
using namespace machinetherapist;
using json = nlohmann::json;

// Global instance to keep the engine alive
static unique_ptr<VehButNot> g_VehEngine = nullptr;

// This string is allocated and returned to the MCP server
static const char* AllocateResult(const json& result)
{
	string response = result.dump();
	char* buf = new char[response.size() + 1];
	strcpy_s(buf, response.size() + 1, response.c_str());
	return buf;
}

static void VehFreeResult(const char* resultStr)
{
	delete[] resultStr;
}

// Our custom interception handler for the Target API
static bool OnVehInterception(PVOID targetAddress, PCONTEXT ctx, PVOID userData)
{
	cerr << format("\n[VEHBUTNOT EXTENSION] Intercepted Execution at 0x{:016X}\n", reinterpret_cast<uintptr_t>(targetAddress));

	// Log registers to stderr (visible in MCP terminal)
	cerr << format("  RIP: 0x{:016X}\n", ctx->Rip);
	cerr << format("  RCX: 0x{:016X} (Arg 1)\n", ctx->Rcx);
	cerr << format("  RDX: 0x{:016X} (Arg 2)\n", ctx->Rdx);
	cerr << format("  R8:  0x{:016X} (Arg 3)\n", ctx->R8);
	cerr << format("  R9:  0x{:016X} (Arg 4)\n", ctx->R9);

	// Allow original function to execute
	return true;
}

// The Tool Handler: setups a hardware breakpoint hook on a specific API
static const char* VehInstallHookHandler(const char* jsonArgs)
{
	try {
		json args = json::parse(jsonArgs);
		string library = args.value("library", "ntdll.dll");
		string function = args.value("function", "NtReadVirtualMemory");

		HMODULE hModule = GetModuleHandleA(library.c_str());
		if (!hModule) {
			return AllocateResult({{"content", json::array({{{"type", "text"}, {"text", "Failed to get module handle."}}})}});
		}

		PVOID targetApi = reinterpret_cast<PVOID>(GetProcAddress(hModule, function.c_str()));
		if (!targetApi) {
			return AllocateResult({{"content", json::array({{{"type", "text"}, {"text", "Failed to get API address."}}})}});
		}

		if (g_VehEngine) {
			g_VehEngine->Shutdown();
			g_VehEngine.reset();
		}

		g_VehEngine = make_unique<VehButNot>();

		VehButNotConfig config{.targetApi = targetApi, .handler = OnVehInterception, .persistentHook = true, .enableDrHiding = true};

		if (!g_VehEngine->Initialize(config)) {
			return AllocateResult({{"content", json::array({{{"type", "text"}, {"text", "VehButNot Init failed."}}})}});
		}

		if (!g_VehEngine->ArmViaWnf()) {
			return AllocateResult({{"content", json::array({{{"type", "text"}, {"text", "VehButNot Arm failed."}}})}});
		}

		return AllocateResult(
			{{"content", json::array({{{"type", "text"}, {"text", format("Successfully installed VehButNot HWBP hook on {}!{}", library, function)}}})}});
	}
	catch (const exception& e) {
		return AllocateResult({{"content", json::array({{{"type", "text"}, {"text", e.what()}}})}});
	}
}

static const char* VehShutdownHandler(const char* jsonArgs)
{
	if (g_VehEngine) {
		g_VehEngine->Shutdown();
		g_VehEngine.reset();
		return AllocateResult({{"content", json::array({{{"type", "text"}, {"text", "VehButNot engine shut down."}}})}});
	}
	return AllocateResult({{"content", json::array({{{"type", "text"}, {"text", "VehButNot engine not running."}}})}});
}

static const char* VehStatusHandler(const char* jsonArgs)
{
	if (g_VehEngine) {
		int count = g_VehEngine->GetInterceptionCount();
		return AllocateResult({{"content", json::array({{{"type", "text"}, {"text", format("Active. Interceptions so far: {}", count)}}})}});
	}
	return AllocateResult({{"content", json::array({{{"type", "text"}, {"text", "Inactive."}}})}});
}

extern "C" __declspec(dllexport) bool InitMcpExtension(const McpServerApi* api)
{
	if (!api || !api->registerTool)
		return false;

	// 1. Install Hook Tool
	McpToolRegistration t_install = {
		"ext_vehbutnot_install",
		"Installs a stealth hardware breakpoint hook on an API via VehButNot to intercept calls.",
		"1.0.0",
		R"({"type": "object", "properties": {"library": {"type": "string", "default": "ntdll.dll"}, "function": {"type": "string", "default": "NtReadVirtualMemory"}}, "required": ["library", "function"]})",
		VehInstallHookHandler,
		VehFreeResult};
	api->registerTool(api->serverContext, &t_install);

	// 2. Status Tool
	McpToolRegistration t_status = {"ext_vehbutnot_status",
									"Checks if VehButNot is active and returns the interception count.",
									"1.0.0",
									R"({"type": "object", "properties": {}})",
									VehStatusHandler,
									VehFreeResult};
	api->registerTool(api->serverContext, &t_status);

	// 3. Shutdown Tool
	McpToolRegistration t_shutdown = {"ext_vehbutnot_shutdown",
									  "Removes the hardware breakpoints and shuts down VehButNot.",
									  "1.0.0",
									  R"({"type": "object", "properties": {}})",
									  VehShutdownHandler,
									  VehFreeResult};
	api->registerTool(api->serverContext, &t_shutdown);

	return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	return TRUE;
}
