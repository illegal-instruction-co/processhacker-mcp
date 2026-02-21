#pragma once

#include <nlohmann/json.hpp>

namespace machinetherapist {

	using json = nlohmann::json;

	class BuiltinExt {
	public:
		static json ListProcesses(const json& args);
		static json ListModules(const json& args);
		static json ReadMemory(const json& args);

		static json ListThreads(const json& args);
		static json QueryMemoryRegions(const json& args);
		static json SuspendResumeThread(const json& args);
		// Handle listing requires NtQuerySystemInformation, will add barebones struct
		static json ListHandles(const json& args);
	};

} // namespace machinetherapist
