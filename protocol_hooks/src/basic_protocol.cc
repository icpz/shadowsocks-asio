
#include <common_utils/common.h>
#include <common_utils/socks5.h>

#include "protocol_hooks/basic_protocol.h"

using boost::asio::ip::tcp;

uint8_t BasicProtocol::ParseHeader(Buffer &buf, size_t start_offset) {
    uint8_t reply;
    TargetInfo target;
    header_length_ = \
        GetTargetFromSocks5Address(buf.GetData() + start_offset, &reply, target);
    if (!remote_info_) {
        remote_info_ = std::make_shared<TargetInfo>(std::move(target));
    }

    return reply;
}

bool BasicProtocol::GetResolveArgs(std::string &hostname, std::string &port) const {
    if (!NeedResolve()) return false;
    hostname = remote_info_->GetHostname();
    port = std::to_string(remote_info_->GetPort());
    return true;
}

bool BasicProtocol::GetResolveArgs(std::string &hostname, uint16_t &port) const {
    if (!NeedResolve()) return false;
    hostname = remote_info_->GetHostname();
    port = remote_info_->GetPort();
    return true;
}

tcp::endpoint BasicProtocol::GetEndpoint() const {
    if (NeedResolve()) return tcp::endpoint();
    return tcp::endpoint{ remote_info_->GetIp(), remote_info_->GetPort() };
}

