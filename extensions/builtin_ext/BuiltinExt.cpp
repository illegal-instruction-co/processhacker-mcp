#include "BuiltinExt.h"
#include "../../include/McpExtensionApi.h"
#include <windows.h>
#include <tlhelp32.h>

#include <format>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

using namespace std;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define SystemExtendedHandleInformation 64

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
	PVOID Object;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef NTSTATUS(NTAPI* NtQuerySystemInformationFn)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength,
													PULONG ReturnLength);

namespace machinetherapist {

	// Helper to convert C++ std::string responses to C-string allocated for MCP Server
	static const char* AllocateResult(const json& result)
	{
		std::string response = result.dump();
		char* buf = new char[response.size() + 1];
		strcpy_s(buf, response.size() + 1, response.c_str());
		return buf;
	}

	static void BuiltinFreeResult(const char* resultStr)
	{
		delete[] resultStr;
	}

	// C-API Wrappers
	static const char* WrapListProcesses(const char* args)
	{
		return AllocateResult(BuiltinExt::ListProcesses(json::parse(args)));
	}
	static const char* WrapListModules(const char* args)
	{
		return AllocateResult(BuiltinExt::ListModules(json::parse(args)));
	}
	static const char* WrapReadMemory(const char* args)
	{
		return AllocateResult(BuiltinExt::ReadMemory(json::parse(args)));
	}
	static const char* WrapListThreads(const char* args)
	{
		return AllocateResult(BuiltinExt::ListThreads(json::parse(args)));
	}
	static const char* WrapSuspendResumeThread(const char* args)
	{
		return AllocateResult(BuiltinExt::SuspendResumeThread(json::parse(args)));
	}
	static const char* WrapQueryMemoryRegions(const char* args)
	{
		return AllocateResult(BuiltinExt::QueryMemoryRegions(json::parse(args)));
	}
	static const char* WrapListHandles(const char* args)
	{
		return AllocateResult(BuiltinExt::ListHandles(json::parse(args)));
	}

	extern "C" __declspec(dllexport) bool InitMcpExtension(const McpServerApi* api)
	{
		if (!api || !api->registerTool)
			return false;

		McpToolRegistration t_proc = {
			"ph_list_processes", "Lists all running processes on the system.", "1.0.0",
			R"({"type": "object", "properties": {"offset": {"type": "integer"}, "limit": {"type": "integer"}}})",
			WrapListProcesses,
			BuiltinFreeResult, false};
		api->registerTool(api->serverContext, &t_proc);

		McpToolRegistration t_mod = {
			"ph_list_modules",
			"Lists all loaded modules (DLLs) for a specific process ID.",
			"1.0.0",
			R"({"type": "object", "properties": {"pid": {"type": "integer", "description": "The Process ID to inspect"}, "offset": {"type": "integer"}, "limit": {"type": "integer"}}, "required": ["pid"]})",
			WrapListModules,
			BuiltinFreeResult, false};
		api->registerTool(api->serverContext, &t_mod);

		McpToolRegistration t_mem = {
			"ph_read_memory",
			"Reads memory from a specific process given an address and size, returning a hex string.",
			"1.0.0",
			R"({"type": "object", "properties": {"pid": {"type": "integer"}, "address": {"type": "string"}, "size": {"type": "integer"}}, "required": ["pid", "address", "size"]})",
			WrapReadMemory,
			BuiltinFreeResult, false};
		api->registerTool(api->serverContext, &t_mem);

		McpToolRegistration t_threads = {"ph_list_threads", "Lists all threads for a specific process ID.",
										 "1.0.0",			R"({"type": "object", "properties": {"pid": {"type": "integer"}}, "required": ["pid"]})",
										 WrapListThreads,	BuiltinFreeResult, false};
		api->registerTool(api->serverContext, &t_threads);

		McpToolRegistration t_suspend = {
			"ph_suspend_resume_thread",
			"Suspends or resumes a specific thread ID.",
			"1.0.0",
			R"({"type": "object", "properties": {"tid": {"type": "integer"}, "action": {"type": "string"}}, "required": ["tid", "action"]})",
			WrapSuspendResumeThread,
			BuiltinFreeResult, true}; // Mutes state, mark as destructive
		api->registerTool(api->serverContext, &t_suspend);

		McpToolRegistration t_regions = {"ph_query_memory_regions",
										 "Lists memory regions (VirtualQueryEx) for a specific process ID.",
										 "1.0.0",
										 R"({"type": "object", "properties": {"pid": {"type": "integer"}, "offset": {"type": "integer"}, "limit": {"type": "integer"}}, "required": ["pid"]})",
										 WrapQueryMemoryRegions,
										 BuiltinFreeResult, false};
		api->registerTool(api->serverContext, &t_regions);

		McpToolRegistration t_handles = {"ph_list_handles", "Lists all handles opened by a specific process ID.",
										 "1.0.0",			R"({"type": "object", "properties": {"pid": {"type": "integer"}, "offset": {"type": "integer"}, "limit": {"type": "integer"}}, "required": ["pid"]})",
										 WrapListHandles,	BuiltinFreeResult, false};
		api->registerTool(api->serverContext, &t_handles);

		return true;
	}

	BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
	{
		return TRUE;
	}

	static json FormatToolResult(const string& text)
	{
		return {{"content", json::array({{{"type", "text"}, {"text", text}}})}};
	}

	json BuiltinExt::ListProcesses(const json& args)
	{
		size_t offset = args.value("offset", 0);
		size_t limit = args.value("limit", 1000);

		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snap == INVALID_HANDLE_VALUE) {
			return FormatToolResult("Failed to create snapshot");
		}

		PROCESSENTRY32 pe32{};
		pe32.dwSize = sizeof(pe32);

		json procs = json::array();
		size_t currentIndex = 0;

		if (Process32First(snap, &pe32)) {
			do {
				if (currentIndex >= offset && procs.size() < limit) {
					procs.push_back({{"pid", pe32.th32ProcessID},
									 {"name", pe32.szExeFile},
									 {"threads", pe32.cntThreads},
									 {"parentPid", pe32.th32ParentProcessID}});
				}
				currentIndex++;
				if (procs.size() >= limit) {
					break;
				}
			} while (Process32Next(snap, &pe32));
		}

		CloseHandle(snap);
		return FormatToolResult(procs.dump(2));
	}

	json BuiltinExt::ListModules(const json& args)
	{
		if (!args.contains("pid") || !args["pid"].is_number_integer()) {
			return FormatToolResult("Invalid 'pid' argument.");
		}

		DWORD pid = args["pid"].get<DWORD>();
		size_t offset = args.value("offset", 0);
		size_t limit = args.value("limit", 1000);

		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
		if (snap == INVALID_HANDLE_VALUE) {
			return FormatToolResult(format("Failed to create snapshot for PID {}, error: {}", pid, GetLastError()));
		}

		MODULEENTRY32 me32{};
		me32.dwSize = sizeof(me32);

		json mods = json::array();
		size_t currentIndex = 0;

		if (Module32First(snap, &me32)) {
			do {
				if (currentIndex >= offset && mods.size() < limit) {
					mods.push_back({{"name", me32.szModule},
									{"path", me32.szExePath},
									{"baseAddress", format("0x{:X}", reinterpret_cast<uintptr_t>(me32.modBaseAddr))},
									{"size", me32.modBaseSize}});
				}
				currentIndex++;
				if (mods.size() >= limit) {
					break;
				}
			} while (Module32Next(snap, &me32));
		}

		CloseHandle(snap);
		return FormatToolResult(mods.dump(2));
	}

	json BuiltinExt::ReadMemory(const json& args)
	{
		if (!args.contains("pid") || !args.contains("address") || !args.contains("size")) {
			return FormatToolResult("Missing arguments");
		}

		DWORD pid = args["pid"].get<DWORD>();
		string addrStr = args["address"].get<string>();
		size_t size = args["size"].get<size_t>();

		if (size == 0 || size > 4096) {
			return FormatToolResult("Size must be between 1 and 4096.");
		}

		uintptr_t address = 0;
		try {
			address = stoull(addrStr, nullptr, 16);
		}
		catch (...) {
			return FormatToolResult("Invalid address format. Use hex.");
		}

		HANDLE hProc = OpenProcess(PROCESS_VM_READ, FALSE, pid);
		if (!hProc) {
			return FormatToolResult(format("Failed to OpenProcess for read, error: {}", GetLastError()));
		}

		vector<uint8_t> buffer(size);
		SIZE_T bytesRead = 0;

		if (ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(address), buffer.data(), size, &bytesRead)) {
			ostringstream oss;
			for (SIZE_T i = 0; i < bytesRead; ++i) {
				oss << hex << setw(2) << setfill('0') << static_cast<int>(buffer[i]);
			}
			CloseHandle(hProc);
			return FormatToolResult(oss.str());
		}

		CloseHandle(hProc);
		return FormatToolResult(format("ReadProcessMemory failed, error: {}", GetLastError()));
	}

	json BuiltinExt::ListThreads(const json& args)
	{
		if (!args.contains("pid") || !args["pid"].is_number_integer()) {
			return FormatToolResult("Invalid 'pid' argument.");
		}

		DWORD pid = args["pid"].get<DWORD>();
		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (snap == INVALID_HANDLE_VALUE) {
			return FormatToolResult(format("Failed to create snapshot, error: {}", GetLastError()));
		}

		THREADENTRY32 te32{};
		te32.dwSize = sizeof(te32);

		json threads = json::array();
		if (Thread32First(snap, &te32)) {
			do {
				if (te32.th32OwnerProcessID == pid) {
					threads.push_back(json{{"tid", te32.th32ThreadID}, {"basePriority", te32.tpBasePri}});
				}
			} while (Thread32Next(snap, &te32));
		}

		CloseHandle(snap);
		return FormatToolResult(threads.dump(2));
	}

	json BuiltinExt::SuspendResumeThread(const json& args)
	{
		if (!args.contains("tid") || !args.contains("action")) {
			return FormatToolResult("Missing 'tid' or 'action' arguments.");
		}

		DWORD tid = args["tid"].get<DWORD>();
		string action = args["action"].get<string>();

		HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
		if (!hThread) {
			return FormatToolResult(format("Failed to OpenThread {}, error: {}", tid, GetLastError()));
		}

		DWORD result = (DWORD)-1;
		if (action == "suspend") {
			result = SuspendThread(hThread);
		}
		else if (action == "resume") {
			result = ResumeThread(hThread);
		}
		else {
			CloseHandle(hThread);
			return FormatToolResult("Invalid action. Use 'suspend' or 'resume'.");
		}

		CloseHandle(hThread);

		if (result == (DWORD)-1) {
			return FormatToolResult(format("Failed to {} thread, error: {}", action, GetLastError()));
		}

		return FormatToolResult(format("Successfully performed {} on thread {}. Previous count: {}", action, tid, result));
	}

	json BuiltinExt::QueryMemoryRegions(const json& args)
	{
		if (!args.contains("pid") || !args["pid"].is_number_integer()) {
			return FormatToolResult("Invalid 'pid' argument.");
		}

		DWORD pid = args["pid"].get<DWORD>();
		size_t offset = args.value("offset", 0);
		size_t limit = args.value("limit", 1000);

		HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (!hProc) {
			return FormatToolResult(format("Failed to OpenProcess for query, error: {}", GetLastError()));
		}

		json regions = json::array();
		MEMORY_BASIC_INFORMATION mbi{};
		uintptr_t currentAddress = 0;
		size_t currentIndex = 0;

		while (VirtualQueryEx(hProc, reinterpret_cast<LPCVOID>(currentAddress), &mbi, sizeof(mbi)) == sizeof(mbi)) {
			if (mbi.State != MEM_FREE) {
				if (currentIndex >= offset && regions.size() < limit) {
					string stateStr, typeStr, protectStr;

					switch (mbi.State) {
					case MEM_COMMIT:
						stateStr = "Commit";
						break;
					case MEM_RESERVE:
						stateStr = "Reserve";
						break;
					default:
						stateStr = "Unknown";
						break;
					}

					switch (mbi.Type) {
					case MEM_IMAGE:
						typeStr = "Image";
						break;
					case MEM_MAPPED:
						typeStr = "Mapped";
						break;
					case MEM_PRIVATE:
						typeStr = "Private";
						break;
					default:
						typeStr = "Unknown";
						break;
					}

					DWORD p = mbi.Protect;
					if (p & PAGE_EXECUTE) protectStr += "X";
					if (p & PAGE_EXECUTE_READ) protectStr += "RX";
					if (p & PAGE_EXECUTE_READWRITE) protectStr += "RWX";
					if (p & PAGE_EXECUTE_WRITECOPY) protectStr += "WCX";
					if (p & PAGE_NOACCESS) protectStr += "NA";
					if (p & PAGE_READONLY) protectStr += "R";
					if (p & PAGE_READWRITE) protectStr += "RW";
					if (p & PAGE_WRITECOPY) protectStr += "WC";

					regions.push_back({{"baseAddress", format("0x{:X}", reinterpret_cast<uintptr_t>(mbi.BaseAddress))},
									   {"size", mbi.RegionSize},
									   {"state", stateStr},
									   {"type", typeStr},
									   {"protection", protectStr.empty() ? to_string(mbi.Protect) : protectStr}});
				}
				currentIndex++;
			}

			if (regions.size() >= limit) {
				break;
			}

			currentAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
		}

		CloseHandle(hProc);
		return FormatToolResult(regions.dump(2));
	}

	json BuiltinExt::ListHandles(const json& args)
	{
		if (!args.contains("pid") || !args["pid"].is_number_integer()) {
			return FormatToolResult("Invalid 'pid' argument.");
		}

		DWORD targetPid = args["pid"].get<DWORD>();
		size_t offset = args.value("offset", 0);
		size_t limit = args.value("limit", 1000);

		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
		if (!ntdll) {
			return FormatToolResult("Failed to get ntdll.dll");
		}

		auto NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
		if (!NtQuerySystemInformation) {
			return FormatToolResult("Failed to resolve NtQuerySystemInformation");
		}

		ULONG returnLength = 0;
		ULONG bufferSize = 0x10000;
		vector<uint8_t> buffer(bufferSize);
		NTSTATUS status = 0;

		do {
			status = NtQuerySystemInformation(SystemExtendedHandleInformation, buffer.data(), bufferSize, &returnLength);
			if (status == (NTSTATUS)0xC0000004) {
				bufferSize = returnLength + 0x10000;
				buffer.resize(bufferSize);
			}
		} while (status == (NTSTATUS)0xC0000004);

		if (!NT_SUCCESS(status)) {
			return FormatToolResult(format("NtQuerySystemInformation failed with status 0x{:X}", status));
		}

		auto* handleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(buffer.data());
		json handles = json::array();
		size_t currentIndex = 0;

		for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; i++) {
			const auto& handle = handleInfo->Handles[i];

			if (handle.UniqueProcessId == targetPid) {
				if (currentIndex >= offset && handles.size() < limit) {
					handles.push_back({{"handle", format("0x{:X}", handle.HandleValue)},
									   {"objectAddress", format("0x{:X}", reinterpret_cast<uintptr_t>(handle.Object))},
									   {"access", format("0x{:X}", handle.GrantedAccess)},
									   {"typeIndex", handle.ObjectTypeIndex}});
				}
				currentIndex++;

				if (handles.size() >= limit) {
					break;
				}
			}
		}

		return FormatToolResult(handles.dump(2));
	}

} // namespace machinetherapist
