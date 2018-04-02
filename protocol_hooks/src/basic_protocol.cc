
#include <common_utils/common.h>
#include <common_utils/socks5.h>

#include "protocol_hooks/basic_protocol.h"

using boost::asio::ip::tcp;

uint8_t BasicProtocol::ParseHeader(Buffer &buf, size_t start_offset) {
    uint8_t reply;
    header_length_ = GetTargetFromSocks5Address(buf.GetData() + start_offset, &reply, target_);

    return reply;
}

bool BasicProtocol::GetResolveArgs(std::string &hostname, std::string &port) const {
    if (!NeedResolve()) return false;
    hostname = target_.GetHostname();
    port = std::to_string(target_.GetPort());
    return true;
}

tcp::endpoint BasicProtocol::GetEndpoint() const {
    if (NeedResolve()) return tcp::endpoint();
    return tcp::endpoint{ target_.GetIp(), target_.GetPort() };
}

