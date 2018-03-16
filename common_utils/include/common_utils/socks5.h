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

    static size_t NeedMore(const uint8_t *buf, size_t curr_size);
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

    static size_t NeedMore(const uint8_t *buf, size_t curr_size);
} __attribute__((__packed__));

struct Reply {
    uint8_t ver;
    uint8_t rep;
    uint8_t rsv;
    uint8_t atype;
    uint8_t variable_field[1];

    static size_t FillBoundAddress(uint8_t *buf, const boost::asio::ip::tcp::endpoint &ep);
} __attribute__((__packed__));

} // socks5

#endif

