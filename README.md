# processhacker mcp

<img width="1024" height="559" alt="image" src="https://github.com/user-attachments/assets/018bd9d5-ed66-43e7-b19d-f5331fb1481a" />

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

## agent guardrails & telemetry (new in v1.1.0)
we added some enterprise-grade agent logic to stop rogue bots from nuking your host machine.

- **Read-Only Mode:** change `"args": []` to `"args": ["--read-only"]` in your mcp config. if the ai tries to write memory or suspend threads (destructive actions), the core blocks it.
- **Audit Log:** all tool calls (and their args) are saved to `processhacker_audit.log`. destructive actions are tagged with `[WARNING: DESTRUCTIVE]`.
- **Loop Breaker (Rate Limit):** if an ai agent panics and calls 50 tools in 1 minute (brute-forcing memory), the core locks it out for 30 seconds. write a c++ extension for heavy scanning, don't spam rpc.
- **Loud Failures:** if reading unmapped memory fails, the ai gets a clear hint to use `ph_query_memory_regions` instead of just a generic error.

## how to make extension (for bypass etc)
core is just router. all tools are in dll plugins.

if u want make stealth bypass (like vehbutnot or direct syscall):
1. copy `extensions/sample_ext` folder.
2. write your code in c or c++.
3. setup `McpToolRegistration` and set `isDestructive = true` if your tool mutates state (writes memory, sets hooks).
4. u must export `InitMcpExtension`.
5. put your compiled `.dll` inside `extensions/` folder.
6. exe will auto load your dll on start and ai agent will see your new tool.

> **new in v1.6.0:** the ai agent can now write its own extensions dynamically! by using the `ext_auto_compiler` tool, the agent can send raw C code which the router compiles using a bundled TCC (Tiny C Compiler) and hot-loads directly into active memory. you can literally ask the ai to write its own custom bypass and it will compile itself on the fly!

## contribute
if u write good stealth extension and think it can bypass anything or help others, please send pull request (pr). we need more plugins for stealth. 

## just wondering... (faq)
i was thinking about this architecture and had a weird thought:

**could someone actually use this to create autonomous malware or game cheats just by writing prompts?**
like asking the ai: "inject here, find the decryption routine, and dump the keys as json". since the actual "malware behavior" isn't in the compiled c++ code but in the prompt text, no classic anti-virus could catch the payload statically. 

and if an anti-cheat updates, the ai could just read the new memory layout and adapt its logic instantly without needing a recompile.

is this genuinely possible now or just a weird architectural nightmare? lol 
if u have thoughts on this, hit me up or open an issue.

## disclaimer

**educational and research purposes only.** published to document the technique, not to hand it out as a toolkit.

what you do with this is your problem. no warranty, no support, no liability.

## license

MIT. do whatever. don't blame us.
