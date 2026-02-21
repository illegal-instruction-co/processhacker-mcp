#include "McpServer.h"

#include <iostream>
#include <windows.h>
#include <filesystem>
#include <fcntl.h>
#include <io.h>

using namespace std;

using namespace machinetherapist;

int main(int argc, char* argv[])
{
#ifdef _WIN32
	_setmode(_fileno(stdin), _O_BINARY);
	_setmode(_fileno(stdout), _O_BINARY);
	_setmode(_fileno(stderr), _O_BINARY);
#endif

	McpServer server;

	cerr << "[*] ProcessHacker MCP router started\n";

	WCHAR exePath[MAX_PATH];
	GetModuleFileNameW(nullptr, exePath, MAX_PATH);
	filesystem::path basePath = filesystem::path(exePath).parent_path();
	filesystem::path extPath = basePath / "extensions";

	server.LoadExtensions(extPath.string());

	server.Start();

	return 0;
}
