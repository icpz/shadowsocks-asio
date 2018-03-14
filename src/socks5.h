#ifndef __SOCKS5_H__
#define __SOCKS5_H__

#include <boost/asio.hpp>
#include <boost/endian/arithmetic.hpp>

namespace socks5 {

enum { VERSION = 0x05 };

enum Methods {
    NO_AUTH_METHOD        = 0x00,
    GSSAPI_METHOD         = 0x01,
    USER_PASSWORD_METHOD  = 0x02,
    NO_ACCCEPTABLE_METHOD = 0xff
};

enum CommandCode {
    CONNECT_CMD       = 0x01,
    BIND_CMD          = 0x02,
    UDP_ASSOCIATE_CMD = 0x03
};

enum ReplyCode {
    SUCCEEDED_REP           = 0x00,
    GENERAL_SOCKS_FAIL_REP  = 0x01,
    CONN_NOT_ALLOWED_REP    = 0x02,
    NETWORK_UNREACHABLE_REP = 0x03,
    HOST_UNREACHABLE_REP    = 0x04,
    CONN_REFUSED_REP        = 0x05,
    TTL_EXPIRED_REP         = 0x06,
    CMD_NOT_SUPPORTED_REP   = 0x07,
    ATYPE_NOT_SUPPORTED_REP = 0x08
};

enum AddressType {
    IPV4_ATYPE    = 0x01,
    DOMAIN_ATYPE  = 0x03,
    IPV6_ATYPE    = 0x04
};

struct MethodSelectionMessageHeader {
    uint8_t ver;
    uint8_t num_methods;
    uint8_t methods[1];

    static size_t NeedMore(const uint8_t *buf, size_t curr_size) {
        auto *hdr = (MethodSelectionMessageHeader *)(buf);
        if (curr_size < 2) return 2 - curr_size;
        size_t excepted_size = (uint32_t)hdr->num_methods + 2;
        return (curr_size > excepted_size ? 0 : excepted_size - curr_size);
    }
} __attribute__((__packed__));

struct MethodSelectionMessageReply {
    uint8_t ver;
    uint8_t method;
} __attribute__((__packed__));

struct Request {
    uint8_t ver;
    uint8_t cmd;
    uint8_t rsv;
    uint8_t atype;
    uint8_t variable_field[1];

    static size_t NeedMore(const uint8_t *buf, size_t curr_size) {
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
} __attribute__((__packed__));

struct Reply {
    uint8_t ver;
    uint8_t rep;
    uint8_t rsv;
    uint8_t atype;
    uint8_t variable_field[1];

    static size_t FillBoundAddress(uint8_t *buf, const boost::asio::ip::tcp::endpoint &ep) {
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
} __attribute__((__packed__));

} // socks5

#endif

