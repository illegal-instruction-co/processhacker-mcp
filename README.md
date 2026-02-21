# processhacker mcp

this is dynamic mcp server for runtime analysis and process hacking. it is like processhacker but for ai agents.

## setup
1. open folder in visual studio (it has cmakelists)
2. build all (ctrl+shift+b)
3. it makes `ProcessHackerMCP.exe` and `extensions/` folder.
4. run exe. it communicates via stdin/stdout.

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
