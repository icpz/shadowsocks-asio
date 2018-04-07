
#include "common_utils/util.h"

size_t GetTargetFromSocks5Address(const uint8_t *buf, uint8_t *reply, TargetInfo &target) {
    auto *hdr = (socks5::Request *)(buf - 3);
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
        address_str.reserve(port_offset);
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
        LOG(WARNING) << "Unsupport address type: " << hdr->atype;
        if (reply) {
            *reply = socks5::ATYPE_NOT_SUPPORTED_REP;
        }
        return 0;
    }
    uint16_t port;
    memcpy(&port, &hdr->variable_field[port_offset], sizeof port);
    boost::endian::big_to_native_inplace(port);
    size_t header_length = port_offset + 3; // one for atype and two for port

    if (need_resolve) {
        target.SetTarget(std::move(address_str), port);
    } else {
        target.SetTarget(address, port);
    }

    if (reply) {
        *reply = socks5::SUCCEEDED_REP;
    }
    return header_length;
}

