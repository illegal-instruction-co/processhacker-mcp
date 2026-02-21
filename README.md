# processhacker mcp

this is dynamic mcp server for runtime analysis and process hacking. it is like processhacker but for ai agents.

## setup
1. open folder in visual studio (it has cmakelists)
2. build all (ctrl+shift+b)
3. it makes `ProcessHackerMCP.exe` and `extensions/` folder.
4. run exe. it communicates via stdin/stdout.

## editor integration
you can configure your ai agent/editor to use this server. below are the `mcp_config.json` (or equivalent) settings. **make sure to put the absolute path to the `.exe`.**

### cursor / gemini (antigravity) / claude desktop
add this to your mcp configuration file:
```json
{
  "mcpServers": {
    "processhacker": {
      "command": "C:\\absolute\\path\\to\\ProcessHackerMCP.exe",
      "args": []
    }
  }
}
```

### vscode (cline)
go to cline settings -> mcp servers and add:
```json
{
  "mcpServers": {
    "processhacker": {
      "command": "C:\\absolute\\path\\to\\ProcessHackerMCP.exe",
      "args": []
    }
  }
}
```

> **note:** some editors might freeze if the mcp server sends a huge payload (e.g. reading 1GB of memory). the core now has a 2MB payload protection limit, but try to use `limit` and `offset` arguments when querying big processes.

## how to make extension (for bypass etc)
core is just router. all tools are in dll plugins.

if u want make stealth bypass (like vehbutnot or direct syscall):
1. copy `extensions/sample_ext` folder.
2. write your code in c or c++.
3. u must export `InitMcpExtension`.
4. put your compiled `.dll` inside `extensions/` folder.
5. exe will auto load your dll on start and ai agent will see your new tool.

## contribute
if u write good stealth extension and think it can bypass anything or help others, please send pull request (pr). we need more plugins for stealth. 

## disclaimer

**educational and research purposes only.** published to document the technique, not to hand it out as a toolkit.

what you do with this is your problem. no warranty, no support, no liability.

## license

MIT. do whatever. don't blame us.
