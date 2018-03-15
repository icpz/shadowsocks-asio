#ifndef __SERVER_H__
#define __SERVER_H__

#include <cstdint>
#include <boost/asio.hpp>

#include "common.h"
#include "socks5.h"
#include "buffer.h"
#include "basic_protocol.h"


class Socks5ProxyServer {
    typedef boost::asio::ip::tcp tcp;
public:
    Socks5ProxyServer(boost::asio::io_context &ctx, uint16_t port,
                      std::unique_ptr<BasicProtocolFactory> protocol_factory)
        : acceptor_(ctx, tcp::endpoint(tcp::v4(), port)),
          protocol_factory_(std::move(protocol_factory)) {
        LOG(INFO) << "Server running at " << acceptor_.local_endpoint();
        running_ = true;
        DoAccept();
    }

    void stop() {
        acceptor_.cancel();
        running_ = false;
    }

private:
    void DoAccept();

    tcp::acceptor acceptor_;
    bool running_;
    std::unique_ptr<BasicProtocolFactory> protocol_factory_;
};

#endif

