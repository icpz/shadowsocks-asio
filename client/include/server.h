#ifndef __SERVER_H__
#define __SERVER_H__

#include <cstdint>
#include <boost/asio.hpp>

#include <common_utils/common.h>
#include <common_utils/socks5.h>
#include <common_utils/buffer.h>
#include <protocol_hooks/basic_protocol.h>


class Socks5ProxyServer {
    typedef boost::asio::ip::tcp tcp;
    using ProtocolPtr = std::unique_ptr<BasicProtocol>;
    using ProtocolGenerator = std::function<ProtocolPtr(void)>;
public:
    Socks5ProxyServer(boost::asio::io_context &ctx, uint16_t port,
                      ProtocolGenerator protocol_generator)
        : acceptor_(ctx, tcp::endpoint(tcp::v4(), port)),
          protocol_generator_(std::move(protocol_generator)) {
        LOG(INFO) << "Server running at " << acceptor_.local_endpoint();
        running_ = true;
        DoAccept();
    }

    void Stop() {
        acceptor_.cancel();
        running_ = false;
    }

    bool Stopped() const {
        return !running_;
    }

private:
    void DoAccept();

    tcp::acceptor acceptor_;
    bool running_;
    ProtocolGenerator protocol_generator_;
};

#endif

