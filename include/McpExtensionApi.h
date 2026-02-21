#pragma once

// Pure C-API for ABI compatibility across different compilers
// This allows anyone to write an extension DLL in C, C++, Rust, Zig, etc.
#ifdef __cplusplus
extern "C" {
#endif

// Function pointer for the extension's tool handler
// Takes a JSON string of arguments, returns a JSON string of results
typedef const char* (*ExtToolHandlerFn)(const char* jsonArgs);

// Function pointer to free the result string (since the DLL allocated it)
typedef void (*ExtFreeResultFn)(const char* resultStr);

// Structure passed back to the main MCP server to register a tool
struct McpToolRegistration {
	const char* name;
	const char* description;
	const char* version;
	const char* inputSchemaJson;
	ExtToolHandlerFn handler;
	ExtFreeResultFn freeResult;
	bool isDestructive; // Guardrail: does this tool mutate/harm system state?
};

// Callback provided to the DLL by the MCP Server
typedef void (*RegisterToolCallback)(void* serverContext, const struct McpToolRegistration* tool);

// The Core API structure given to the DLL when it initializes
struct McpServerApi {
	void* serverContext;
	RegisterToolCallback registerTool;
};

// =========================================================================
// REQUIRED EXPORT FOR DLLs
// Every extension DLL MUST export this function:
//
// __declspec(dllexport) bool InitMcpExtension(const McpServerApi* api);
// =========================================================================

typedef bool (*InitMcpExtensionFn)(const struct McpServerApi* api);

#ifdef __cplusplus
}
#endif
