#ifndef __UTIL_H__
#define __UTIL_H__

#include <boost/asio.hpp>

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

#endif

