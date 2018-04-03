#ifndef __SERVER_H__
#define __SERVER_H__

#include <unordered_map>
#include <boost/asio.hpp>

#include <protocol_hooks/basic_protocol.h>

class Session;

class ForwardServer {
    typedef boost::asio::ip::tcp tcp;
    using ProtocolPtr = std::unique_ptr<BasicProtocol>;
    using ProtocolGenerator = std::function<ProtocolPtr(void)>;
public:
    ForwardServer(boost::asio::io_context &ctx, tcp::endpoint ep,
                  ProtocolGenerator protocol_generator)
        : acceptor_(ctx, std::move(ep)),
          protocol_generator_(std::move(protocol_generator)) {
        LOG(INFO) << "Server running at " << acceptor_.local_endpoint();
        running_ = true;
        DoAccept();
    }

    void Stop();

    bool Stopped() const {
        return !running_;
    }

private:
    void DoAccept();
    void ReleaseSession(Session *ptr);

    tcp::acceptor acceptor_;
    bool running_;
    ProtocolGenerator protocol_generator_;
    std::unordered_map<Session *, std::weak_ptr<Session>> sessions_;
};

#endif

