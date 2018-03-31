#ifndef __UTIL_H__
#define __UTIL_H__

#include <boost/asio.hpp>
#include <boost/variant.hpp>

#include "common_utils/buffer.h"
#include "common_utils/common.h"
#include "common_utils/socks5.h"

struct Peer {
    Peer(boost::asio::ip::tcp::socket socket, size_t ttl)
        : socket(std::move(socket)),
          ttl(ttl),
          timer(socket.get_executor().context()) {
    }

    Peer(boost::asio::io_context &ctx, size_t ttl)
        : socket(ctx), ttl(ttl), timer(ctx) {
    }

    void CancelAll() {
        socket.cancel();
        timer.cancel();
    }

    boost::asio::ip::tcp::socket socket;
    Buffer buf;
    boost::posix_time::millisec ttl;
    boost::asio::deadline_timer timer;
};

class TargetInfo {
public:
    using IpAddress = boost::asio::ip::address;
    bool NeedResolve() const {
        return state_ == 2;
    }

    bool IsEmpty() const {
        return state_ == 0;
    }

    void SetTarget(IpAddress ip, uint16_t port) {
        address_ = std::move(ip);
        port_ = port;
        state_ = 1;
    }

    void SetTarget(std::string host, uint16_t port) {
        address_ = std::move(host);
        port_ = port;
        state_ = 2;
    }

    std::string GetHostname() const {
        return boost::get<std::string>(address_);
    }

    IpAddress GetIp() const {
        return boost::get<IpAddress>(address_);
    }

    uint16_t GetPort() const {
        return port_;
    }

private:
    uint32_t state_ = 0;
    boost::variant<IpAddress, std::string> address_;
    uint16_t port_;
};

#endif

