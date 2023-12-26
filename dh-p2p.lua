--[[ Dahua HTTP ]] --
local dhttp = Proto("dhttp", "Dahua HTTP")
http = Dissector.get("http")

dhttp:register_heuristic("udp", function(tvb, pinfo, tree)
    local prefix = tvb(0, 4):string()

    if prefix ~= "DHGE" and prefix ~= "DHPO" and prefix ~= "GET " and prefix ~= "POST" and prefix ~= "HTTP" then
        return false
    end

    if prefix == "DHGE" or prefix == "DHPO"  then
        tvb = tvb:bytes(2):tvb("Dahua HTTP")
    end

    local find = "Content%-Type: \r\n"
    local replace = "Content-Type: application/xml\r\n"

    local data = tvb():string()
    local index = data:find(find)

    if index ~= nil then
        local hex = ""

        data = data:gsub(find, replace)
        for i = 1, data:len() do
            hex = hex .. string.format("%02x", data:byte(i))
        end

        tvb = ByteArray.new(hex):tvb("Dahua HTTP")
    end

    http(tvb, pinfo, tree)
    return true
end)

--[[ Inverted STUN ]] --
local istun = Proto("istun", "Inverted STUN")
stun = Dissector.get("stun-udp")

istun:register_heuristic("udp", function(buffer, pinfo, tree)
    local prefix = buffer:bytes(0, 1):uint()
    if prefix ~= 0xFF and prefix ~= 0xFE then
        return false
    end

    local hex = ""
    for i = 0, buffer:len() - 1 do
        hex = hex .. string.format("%02x", 255 - buffer:bytes():get_index(i))
    end

    local tvb = ByteArray.new(hex):tvb("Inverted Payload")

    stun(tvb, pinfo, tree)
    return true
end)

--[[ Phony TCP ]] --
ptcp_protocol = Proto("ptcp", "PhonyTCP Protocol")

bytes_sent = ProtoField.uint32("ptcp.bytes_sent", "Bytes Sent", base.DEC)
bytes_recv = ProtoField.uint32("ptcp.bytes_recv", "Bytes Received", base.DEC)
package_id = ProtoField.uint32("ptcp.package_id", "Package ID", base.HEX)
local_message_id = ProtoField.uint32("ptcp.local_message_id", "Local Message ID", base.DEC)
remote_message_id = ProtoField.uint32("ptcp.remote_message_id", "Remote Message ID", base.DEC)

ptcp_type = ProtoField.uint8("ptcp.type", "Type", base.HEX)
ptcp_length = ProtoField.uint24("ptcp.length", "Length", base.DEC)
ptcp_realm = ProtoField.uint32("ptcp.realm", "Realm", base.HEX)
ptcp_padding = ProtoField.uint32("ptcp.padding", "Padding", base.DEC)
ptcp_payload = ProtoField.bytes("ptcp.payload", "Hex", base.SPACE)
ptcp_payload_string = ProtoField.string("ptcp.payload.string", "Str", base.ASCII)

ptcp_protocol.fields = {
    bytes_sent, bytes_recv, package_id, local_message_id, remote_message_id,
    ptcp_type, ptcp_length, ptcp_realm, ptcp_padding, ptcp_payload, ptcp_payload_string,
}

local function heuristic_checker(buffer, pinfo, tree)
    length = buffer:len()
    if length < 4 then return false end

    if buffer(0, 4):string() == "PTCP" then
        ptcp_protocol.dissector(buffer, pinfo, tree)
        return true
    else
        return false
    end
end

function ptcp_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length < 4 then return end

    pinfo.cols.protocol = "PTCP"
    local subtree = tree:add(ptcp_protocol, buffer(), "PhonyTCP Protocol")
    local header = subtree:add(buffer(0, 24), "Header")

    header:add(bytes_sent, buffer(4, 4))
    header:add(bytes_recv, buffer(8, 4))
    header:add(package_id, buffer(12, 4))
    header:add(local_message_id, buffer(16, 4))
    header:add(remote_message_id, buffer(20, 4))
    
    if length <= 24 then return end

    local data = subtree:add(buffer(24, length - 24), "Data")

    data:add(ptcp_type, buffer(24, 1))
    data:add(ptcp_length, buffer(25, 3))
    
    if length <= 28 then return end

    data:add(ptcp_realm, buffer(28, 4))
    data:add(ptcp_padding, buffer(32, 4))

    if length <= 36 then return end

    data:add(ptcp_payload, buffer(36, length - 36))

    -- check if first byte is printable
    if buffer(36, 1):string():match("%g") then
        data:add(ptcp_payload_string, buffer(36, length - 36))
    end
end

ptcp_protocol:register_heuristic("udp", heuristic_checker)
