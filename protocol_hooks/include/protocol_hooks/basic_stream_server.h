#ifndef __BASIC_STREAM_SERVER__
#define __BASIC_STREAM_SERVER__

#include <unordered_map>
#include <boost/asio.hpp>

#include "protocol_hooks/basic_protocol.h"

#define DECLARE_STREAM_SERVER(Server, Session) \
class Server { \
    typedef boost::asio::ip::tcp tcp; \
    using ProtocolPtr = std::unique_ptr<BasicProtocol>; \
    using ProtocolGenerator = std::function<ProtocolPtr(void)>; \
public: \
    Server(boost::asio::io_context &ctx, tcp::endpoint ep, \
           ProtocolGenerator protocol_generator, size_t ttl = 60000) \
        : acceptor_(ctx, std::move(ep)), timeout_(ttl), \
          protocol_generator_(std::move(protocol_generator)) { \
        LOG(INFO) << "Server running at " << acceptor_.local_endpoint(); \
        running_ = true; \
        DoAccept(); \
    } \
 \
    void Stop(); \
 \
    bool Stopped() const { \
        return !running_; \
    } \
 \
private: \
    void DoAccept(); \
    void ReleaseSession(Session *ptr); \
 \
    tcp::acceptor acceptor_; \
    bool running_; \
    size_t timeout_; \
    ProtocolGenerator protocol_generator_; \
    std::unordered_map<Session *, std::weak_ptr<Session>> sessions_; \
}

#define DEFINE_STREAM_SERVER(Server, Session) \
void Server::DoAccept() { \
    acceptor_.async_accept([this](bsys::error_code ec, tcp::socket socket) { \
        if (!ec) { \
            VLOG(1) << "A new client accepted: " << socket.remote_endpoint(); \
            std::shared_ptr<Session> session{ \
                new Session(std::move(socket), protocol_generator_(), timeout_), \
                std::bind(&Server::ReleaseSession, this, std::placeholders::_1) \
            }; \
            sessions_.emplace(session.get(), session); \
            session->Start(); \
        } \
        if (running_) { \
            DoAccept(); \
        } \
    }); \
} \
 \
void Server::Stop() { \
    if (Stopped()) { return; } \
    acceptor_.cancel(); \
    running_ = false; \
    for (auto &kv : sessions_) { \
        auto p = kv.second.lock(); \
        if (p) { \
            p->Close(); \
        } \
    } \
} \
 \
void Server::ReleaseSession(Session *ptr) { \
    sessions_.erase(ptr); \
    delete ptr; \
}

struct StreamServerArgs {
    boost::asio::ip::tcp::endpoint bind_ep;
    std::function<std::unique_ptr<BasicProtocol>()> generator;
    size_t timeout;
};

#endif

