#include "McpServer.h"
#include "McpExtensionApi.h"

#include <windows.h>

#include <filesystem>
#include <format>
#include <iostream>
#include <vector>

using namespace std;
namespace fs = filesystem;

namespace machinetherapist {

	McpServer::McpServer()
	{
	}

	void McpServer::RegisterTool(const string& name, const string& description, const json& inputSchema, bool isDestructive, ToolHandler handler)
	{
		_tools[name] = {name, description, inputSchema, isDestructive, move(handler)};
	}

	static void ExtensionRegisterToolCallback(void* serverContext, const McpToolRegistration* extTool)
	{
		auto* server = static_cast<McpServer*>(serverContext);

		string name = extTool->name ? extTool->name : "";
		string desc = extTool->description ? extTool->description : "";
		string version = extTool->version ? extTool->version : "1.0.0";

		string fullDesc = format("[v{}] {}", version, desc);

		json schema = json::object();
		if (extTool->inputSchemaJson) {
			try {
				schema = json::parse(extTool->inputSchemaJson);
			}
			catch (...) {
			}
		}

		auto handlerFn = extTool->handler;
		auto freeFn = extTool->freeResult;
		bool isDestructive = extTool->isDestructive;

		server->RegisterTool(name, fullDesc, schema, isDestructive, [handlerFn, freeFn](const json& args) -> json {
			if (!handlerFn) {
				return {{"content", json::array({{{"type", "text"}, {"text", "Missing handler"}}})}};
			}

			string argsStr = args.dump();
			const char* resultCStr = handlerFn(argsStr.c_str());

			json finalResult = json::object();
			if (resultCStr) {
				try {
					finalResult = json::parse(resultCStr);
				}
				catch (...) {
					finalResult = {{"content", json::array({{{"type", "text"}, {"text", resultCStr}}})}};
				}
				if (freeFn) {
					freeFn(resultCStr);
				}
			}
			else {
				finalResult = {{"content", json::array({{{"type", "text"}, {"text", "Extension returned null"}}})}};
			}

			return finalResult;
		});
	}

	void McpServer::LoadExtensions(const string& directory)
	{
		if (!fs::exists(directory)) {
			return;
		}

		McpServerApi api{};
		api.serverContext = this;
		api.registerTool = ExtensionRegisterToolCallback;

		for (const auto& entry : fs::directory_iterator(directory)) {
			if (entry.is_regular_file() && entry.path().extension() == ".dll") {
				HMODULE hMod = LoadLibraryW(entry.path().c_str());
				if (hMod) {
					auto initExt = reinterpret_cast<InitMcpExtensionFn>(GetProcAddress(hMod, "InitMcpExtension"));
					if (initExt) {
						if (initExt(&api)) {
							_loadedModules.push_back(hMod);
							cerr << "[+] Loaded Stealth Extension: " << entry.path().filename().string() << "\n";
						}
						else {
							cerr << "[-] Extension initialization failed: " << entry.path().filename().string() << "\n";
							FreeLibrary(hMod);
						}
					}
					else {
						cerr << "[-] Missing InitMcpExtension export in: " << entry.path().filename().string() << "\n";
						FreeLibrary(hMod);
					}
				}
				else {
					cerr << "[!] Failed to load DLL: " << entry.path().filename().string() << "\n";
				}
			}
		}
	}

	void McpServer::Start()
	{
		// Parse read-only mode from command line (naive check for now, args can be passed to constructor later if needed)
		int argc = __argc;
		char** argv = __argv;
		for (int i = 1; i < argc; ++i) {
			if (string(argv[i]) == "--read-only") {
				_readOnlyMode = true;
				cerr << "[!] Guardrails ACTIVE: Read-only mode enabled. Destructive tools are blocked.\n";
			}
		}

		_running = true;
		string line;

		while (_running && getline(cin, line)) {
			if (line.empty()) {
				continue;
			}

			try {
				auto message = json::parse(line);
				HandleMessage(message);
			}
			catch (const exception& e) {
				cerr << "[!] JSON parse error: " << e.what() << "\n";
				SendError(json(nullptr), -32700, "Parse error");
			}
		}
	}

	void McpServer::Stop()
	{
		_running = false;
	}

	void McpServer::HandleMessage(const json& message)
	{
		if (!message.contains("jsonrpc") || message["jsonrpc"] != "2.0") {
			SendError(message.contains("id") ? message["id"] : json(nullptr), -32600, "Invalid Request");
			return;
		}

		string method = message.value("method", "");
		json id = message.value("id", json(nullptr));
		json params = message.value("params", json::object());

		if (method == "initialize") {
			json result = {{"protocolVersion", "2024-11-05"},
						   {"capabilities", {{"tools", json::object()}}},
						   {"serverInfo", {{"name", "machinetherapist-processhacker"}, {"version", "1.0.0"}}}};
			SendResponse(id, result);
		}
		else if (method == "notifications/initialized") {
			cerr << "[+] MCP Server Initialized\n";
		}
		else if (method == "tools/list") {
			json toolsArray = json::array();
			for (const auto& [name, info] : _tools) {
				toolsArray.push_back({{"name", info.name}, {"description", info.description}, {"inputSchema", info.inputSchema}});
			}
			SendResponse(id, {{"tools", toolsArray}});
		}
		else if (method == "tools/call") {
			string name = params.value("name", "");
			json arguments = params.value("arguments", json::object());

			if (_tools.contains(name)) {
				// Guardrail Check
				if (_readOnlyMode && _tools[name].isDestructive) {
					json errorResult = {
						{"content", json::array({{{"type", "text"}, {"text", "Guardrail Violation: This server is running in --read-only mode. Destructive actions like suspending threads or writing memory are blocked."}}})},
						{"isError", true}};
					cerr << "[-] Blocked destructive tool call: " << name << " (Read-only mode)\n";
					SendResponse(id, errorResult);
					return;
				}

				try {
					// Telemetry (Tracing) Start
					auto startTime = std::chrono::high_resolution_clock::now();
					
					json result = _tools[name].handler(arguments);
					
					// Telemetry (Tracing) End
					auto endTime = std::chrono::high_resolution_clock::now();
					auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
					
					cerr << "[Trace] Tool '" << name << "' executed in " << durationMs << "ms.\n";

					SendResponse(id, result);
				}
				catch (const exception& e) {
					json errorResult = {{"content", json::array({{{"type", "text"}, {"text", format("Error executing tool: {}", e.what())}}})},
										{"isError", true}};
					SendResponse(id, errorResult);
				}
			}
			else {
				SendError(id, -32601, "Method not found");
			}
		}
		else if (!id.is_null()) {
			SendError(id, -32601, "Method not found");
		}
	}

	void McpServer::SendResponse(const json& id, const json& result)
	{
		if (id.is_null()) {
			return;
		}

		json response = {{"jsonrpc", "2.0"}, {"id", id}, {"result", result}};
		string responseStr = response.dump();

		// Prevent massive payloads from crashing the client (e.g. LLM context / editor OOM)
		// Limit set to 2 MB (2 * 1024 * 1024 bytes)
		const size_t MAX_PAYLOAD_SIZE = 2 * 1024 * 1024;

		if (responseStr.length() > MAX_PAYLOAD_SIZE) {
			cerr << "[-] Response payload too large: " << responseStr.length() << " bytes. Blocking to prevent client crash.\n";
			
			// Try to send a clean error response instead
			SendError(id, -32603, format("Response payload too large ({} bytes). Maximum allowed is {} bytes. Please narrow down your request (e.g., using smaller limit/size parameters).", responseStr.length(), MAX_PAYLOAD_SIZE));
			return;
		}

		cout << responseStr << "\n" << flush;
	}

	void McpServer::SendError(const json& id, int code, const string& message)
	{
		if (id.is_null()) {
			return;
		}

		json error = {{"jsonrpc", "2.0"}, {"id", id}, {"error", {{"code", code}, {"message", message}}}};
		cout << error.dump() << "\n" << flush;
	}

	void McpServer::SendNotification(const string& method, const json& params)
	{
		json notification = {{"jsonrpc", "2.0"}, {"method", method}, {"params", params}};
		cout << notification.dump() << "\n" << flush;
	}

} // namespace machinetherapist
