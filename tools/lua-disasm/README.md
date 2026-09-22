# LuaJIT disassembly for xLua-compiled chunks

`walker.lua` disassembles the game's LuaJIT bytecode using `jit.util`
directly. The stock `luajit -bl` crashes on xLua-compiled chunks
(`bc.lua:88: kc nil`); this walker tolerates them.

Usage:
```sh
unzip -p <game>/Aniimo_Data/cvs/res/lua/LuaScripts.xdf xfs/luascripts/Entities/LoginAgent.lua > LoginAgent.lua
luajit walker.lua LoginAgent.lua LoginAgent.lst
```

Notes:
- child prototypes surface via `funck(f, -i)` with Lua type `"proto"`.
- `KSTR` lines are the constant strings (protocol field names, URLs).
- `KTAB[...]` lines are table constants (key mappings).
