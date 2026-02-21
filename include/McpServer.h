#pragma once

#include <chrono>
#include <fstream>
#include <functional>
#include <nlohmann/json.hpp>
#include <string>
#include <unordered_map>
#include <vector>

namespace machinetherapist {

	using json = nlohmann::json;

	class McpServer {
	public:
		using ToolHandler = std::function<json(const json&)>;

		McpServer();
		~McpServer() = default;

		void Start();
		void Stop();

		void RegisterTool(const std::string& name, const std::string& description, const json& inputSchema, bool isDestructive, ToolHandler handler);
		void LoadExtensions(const std::string& directory);

	private:
		void HandleMessage(const json& message);
		void SendResponse(const json& id, const json& result);
		void SendError(const json& id, int code, const std::string& message);
		void SendNotification(const std::string& method, const json& params);

		struct ToolInfo {
			std::string name;
			std::string description;
			json inputSchema;
			bool isDestructive;
			ToolHandler handler;
		};

		std::unordered_map<std::string, ToolInfo> _tools;
		std::vector<void*> _loadedModules; // HMODULEs
		bool _running = false;
		bool _readOnlyMode = false; // Guardrail flag

		struct RateLimitState {
			int callsInWindow = 0;
			std::chrono::steady_clock::time_point windowStart;
			std::chrono::steady_clock::time_point lockoutEnd;
		};
		RateLimitState _rateLimit;
		std::ofstream _auditLog;
	};

} // namespace machinetherapist
