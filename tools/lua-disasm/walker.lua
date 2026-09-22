-- Tolerant LuaJIT disassembler using jit.util directly (bc.lua chokes on
-- these xLua-compiled chunks). Usage: luajit walker.lua <file.lua>
local jutil = require("jit.util")
local vmdef = require("jit.vmdef")
local bcnames = vmdef.bcnames

local function q(s) return string.format("%q", s) end

local function dump_kgc(func, depth, out)
  local pre = string.rep("  ", depth)
  for i = 1, 10000 do
    local ok, k = pcall(jutil.funck, func, -i)
    if not ok or k == nil then break end
    local t = type(k)
    if t == "string" and #k >= 1 then
      out:write(pre .. "  KSTR " .. q(k) .. "\n")
    elseif t == "function" or t == "proto" then
      -- child proto; handled by walk
    elseif t == "table" then
      local ok2, parts = pcall(function()
        local t2 = {}
        for kk, vv in pairs(k) do t2[tostring(kk)] = tostring(vv) end
        return t2
      end)
      if ok2 then
        for kk, vv in pairs(parts) do out:write(pre .. "  KTAB[" .. kk .. "] = " .. vv .. "\n") end
      end
    else
      local ok2, s = pcall(function() return tostring(k) end)
      if ok2 and #s < 200 then out:write(pre .. "  K" .. t:upper() .. " " .. s .. "\n") end
    end
  end
end

local function walk(func, depth, out, seen)
  if depth > 30 then return end
  local pre = string.rep("  ", depth)
  local ok, fi = pcall(jutil.funcinfo, func)
  local loc = (ok and fi and fi.loc) or "?"
  out:write(pre .. "-- BYTECODE -- " .. loc .. "\n")
  for pc = 1, 10000000 do
    local ok2, ins, m = pcall(jutil.funcbc, func, pc)
    if not ok2 or not ins then break end
    local opid = ins & 0xff
    local op = bcnames:sub(6 * opid + 1, 6 * opid + 6)
    local a = (ins >> 8) & 0xff
    local d = ins >> 16
    local ma = m & 7
    local mb = (m >> 3) & 15
    local mc = (m >> 7) & 15
    local b = (ins >> 24) & 0xff
    local line = pre .. string.format("%04d %-7s %3d %3d", pc, op:gsub("%s", ""), ma ~= 0 and a or 0, d)
    if mb ~= 0 then line = line .. " b=" .. b end
    -- resolve constants defensively
    local kc
    if mc == 10 then -- BCMstr
      local ok3, v = pcall(jutil.funck, func, -d - 1)
      if ok3 and type(v) == "string" then kc = v end
    elseif mc == 9 then -- BCMnum
      local ok3, v = pcall(jutil.funck, func, d)
      if ok3 and type(v) == "number" then kc = string.format("%g", v) end
    elseif mc == 12 then -- BCMfunc
      local ok3, v = pcall(jutil.funck, func, -d - 1)
      if ok3 and type(v) == "function" then
        local ok4, fi2 = pcall(jutil.funcinfo, v)
        kc = (ok4 and fi2 and fi2.loc) or "child"
      end
    end
    if kc then line = line .. "  ; " .. q(kc) end
    out:write(line .. "\n")
  end
  dump_kgc(func, depth, out)
  -- recurse into child protos
  for i = 1, 10000 do
    local ok3, k = pcall(jutil.funck, func, -i)
    if not ok3 or k == nil then break end
    if type(k) == "proto" or type(k) == "function" then walk(k, depth + 1, out, seen) end
  end
end

local f = assert(loadfile(arg[1]))
local out = io.open(arg[2], "w") or io.stdout
walk(f, 0, out)
if out ~= io.stdout then out:close() end
