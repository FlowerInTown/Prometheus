local lfs = require("lfs")
local Obfuscator = require("obfuscator")

local function is_lua_file(path)
    return path:sub(-4) == ".lua"
end

local function read_file(path)
    local f, err = io.open(path, "rb")
    if not f then
        return nil, ("failed to open file for read: %s, error: %s"):format(path, err)
    end
    local content = f:read("*a")
    f:close()
    return content
end

local function ensure_dir(dir)
    if dir == nil or dir == "" then
        return true
    end

    local current = ""
    for part in dir:gmatch("[^"]+ ") do
        current = current == "" and part or (current .. "/" .. part)
        local attr = lfs.attributes(current)
        if not attr then
            local ok, mkerr = lfs.mkdir(current)
            if not ok then
                return nil, ("failed to create directory: %s, error: %s"):format(current, mkerr)
            end
        elseif attr.mode ~= "directory" then
            return nil, ("path exists but is not directory: %s"):format(current)
        end
    end
    return true
end

local function write_file(path, content)
    local dir = path:match("^(.*)/[^/]+$")
    local ok, err = ensure_dir(dir)
    if not ok then
        return nil, err
    end
    local f, werr = io.open(path, "wb")
    if not f then
        return nil, ("failed to open file for write: %s, error: %s"):format(path, werr)
    end
    f:write(content)
    f:close()
    return true
end

local function obfuscate_source_safe(src)
    local ok, result = pcall(function()
        return Obfuscator:Obfuscate(src)
    end)

    if not ok then
        return nil, result
    end

    if not result or type(result) ~= "string" then
        return nil, "obfuscator returned invalid result"
    end

    return result, nil
end

local function obfuscate_file(full_input_path, input_root, output_root)
    local rel = full_input_path:sub(#input_root + 2)
    local output_path = output_root .. "/" .. rel

    local src, err = read_file(full_input_path)
    if not src then
        io.stderr:write("[WARN] read failed, keep original: ", full_input_path, " - ", tostring(err), "\n")
        local ok_write, werr = write_file(output_path, "")
        if not ok_write then
            io.stderr:write("[ERROR] write empty file failed: ", output_path, " - ", tostring(werr), "\n")
        end
        return false, err
    end

    local obfuscated, obf_err = obfuscate_source_safe(src)
    if not obfuscated then
        io.stderr:write("[WARN] obfuscate failed, keep original: ", full_input_path, " - ", tostring(obf_err), "\n")
        local ok_write, werr = write_file(output_path, src)
        if not ok_write then
            io.stderr:write("[ERROR] write original failed: ", output_path, " - ", tostring(werr), "\n")
            return false, werr
        end
        return false, obf_err
    end

    local ok_write, werr = write_file(output_path, obfuscated)
    if not ok_write then
        io.stderr:write("[ERROR] write obfuscated failed: ", output_path, " - ", tostring(werr), "\n")
        return false, werr
    end

    return true, nil
end

local function walk_and_obfuscate(current_dir, input_root, output_root)
    for entry in lfs.dir(current_dir) do
        if entry ~= "." and entry ~= ".." then
            local full = current_dir .. "/" .. entry
            local attr = lfs.attributes(full)
            if attr and attr.mode == "directory" then
                walk_and_obfuscate(full, input_root, output_root)
            elseif attr and attr.mode == "file" and is_lua_file(full) then
                obfuscate_file(full, input_root, output_root)
            end
        end
    end
end

local function main()
    local input_root = arg[1]
    local output_root = arg[2]

    if not input_root or not output_root then
        io.stderr:write("Usage: lua obfuscate_dir.lua <input_dir> <output_dir>\n")
        os.exit(1)
    end

    input_root = input_root:gsub("/+$", "")
    output_root = output_root:gsub("/+$", "")

    local attr = lfs.attributes(input_root)
    if not attr or attr.mode ~= "directory" then
        io.stderr:write("Input path is not a directory: ", input_root, "\n")
        os.exit(1)
    end

    walk_and_obfuscate(input_root, input_root, output_root)
    io.stdout:write("Done.\n")
end

main()