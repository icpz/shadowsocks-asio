
#include <common_utils/common.h>
#include <common_utils/socks5.h>

#include "protocol_hooks/basic_protocol.h"

using boost::asio::ip::tcp;

uint8_t BasicProtocol::ParseHeader(Buffer &buf, size_t start_offset) {
    auto *hdr = (socks5::Request *)(buf.GetData() + start_offset - 3);
    std::string address_str;
    boost::asio::ip::address address;
    size_t port_offset;

    bool need_resolve = false;;
    switch(hdr->atype) {
    case socks5::IPV4_ATYPE:
        std::array<uint8_t, 4> ipv4_buf;
        port_offset = ipv4_buf.size();
        std::copy_n(&hdr->variable_field[0], port_offset, std::begin(ipv4_buf));
        address = boost::asio::ip::make_address_v4(ipv4_buf);
        break;

    case socks5::DOMAIN_ATYPE:
        need_resolve = true;
        port_offset = hdr->variable_field[0];
        std::copy_n(&hdr->variable_field[1], port_offset,
                    std::back_inserter(address_str));
        port_offset += 1;
        break;

    case socks5::IPV6_ATYPE:
        std::array<uint8_t, 16> ipv6_buf;
        port_offset = ipv6_buf.size();
        std::copy_n(&hdr->variable_field[0], port_offset, std::begin(ipv6_buf));
        address = boost::asio::ip::make_address_v6(ipv6_buf);
        break;

    default:
        LOG(DEBUG) << "Unsupport address type: " << hdr->atype;
        return socks5::ATYPE_NOT_SUPPORTED_REP;
    }
    uint16_t port = boost::endian::big_to_native(*(uint16_t *)(&hdr->variable_field[port_offset]));
    header_length_ = port_offset + 3; // one for atype and two for port

    if (need_resolve) {
        target_.SetTarget(std::move(address_str), port);
    } else {
        target_.SetTarget(address, port);
    }

    return socks5::SUCCEEDED_REP;
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

