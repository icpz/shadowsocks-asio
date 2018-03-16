
#include "common_utils/socks5.h"

namespace socks5 {

size_t MethodSelectionMessageHeader::NeedMore(const uint8_t *buf, size_t curr_size) {
    auto *hdr = (MethodSelectionMessageHeader *)(buf);
    if (curr_size < 2) return 2 - curr_size;
    size_t excepted_size = (uint32_t)hdr->num_methods + 2;
    return (curr_size > excepted_size ? 0 : excepted_size - curr_size);
}

size_t Request::NeedMore(const uint8_t *buf, size_t curr_size) {
    size_t result = 0;
    auto *hdr = (Request *)(buf);
    if (curr_size < 4) return 4 - curr_size;
    size_t excepted_size = 4 + 2;
    switch(hdr->atype) {
    case IPV4_ATYPE:
        excepted_size += 4;
        break;
    case DOMAIN_ATYPE:
        if (curr_size < 5) return 1;
        excepted_size += hdr->variable_field[0];
        break;
    case IPV6_ATYPE:
        excepted_size += 16;
        break;
    }
    result = (curr_size > excepted_size ? 0 : excepted_size - curr_size);
    return result;
}

size_t Reply::FillBoundAddress(uint8_t *buf, const boost::asio::ip::tcp::endpoint &ep) {
    auto *hdr = (Reply *)(buf);
    size_t result = 4;
    auto address = ep.address();
    if (address.is_v4()) {
        hdr->atype = IPV4_ATYPE;
        auto ipv4_buf = address.to_v4().to_bytes();
        result += ipv4_buf.size();
        std::copy(std::begin(ipv4_buf), std::end(ipv4_buf), &hdr->variable_field[0]);
    } else {
        hdr->atype = IPV6_ATYPE;
        auto ipv6_buf = address.to_v6().to_bytes();
        result += ipv6_buf.size();
        std::copy(std::begin(ipv6_buf), std::end(ipv6_buf), &hdr->variable_field[0]);
    }
    *((uint16_t *)(buf + result)) = boost::endian::native_to_big(ep.port());
    result += 2;
    return result;
}

} // socks5

