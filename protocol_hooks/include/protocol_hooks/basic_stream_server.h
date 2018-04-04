#ifndef __BASIC_STREAM_SERVER__
#define __BASIC_STREAM_SERVER__

#include <unordered_map>
#include <boost/asio.hpp>

#include "protocol_hooks/basic_protocol.h"

#define DECLARE_STREAM_SERVER(__server_name, __session_name) \
class __server_name { \
    typedef boost::asio::ip::tcp tcp; \
    using ProtocolPtr = std::unique_ptr<BasicProtocol>; \
    using ProtocolGenerator = std::function<ProtocolPtr(void)>; \
public: \
    __server_name(boost::asio::io_context &ctx, tcp::endpoint ep, \
           ProtocolGenerator protocol_generator, size_t ttl = 60000) \
        : acceptor_(ctx, std::move(ep)), timeout_(ttl), \
          protocol_generator_(std::move(protocol_generator)) { \
        LOG(INFO) << "__server_name running at " << acceptor_.local_endpoint(); \
        running_ = true; \
        DoAccept(); \
    } \
 \
    ~__server_name() { \
        VLOG(3) << "destructing " #__server_name << std::endl; \
        if (!sessions_.empty()) { \
            LOG(ERROR) << "sessions is not recalled before destructing"; \
        } \
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
    void ReleaseSession(__session_name *ptr); \
 \
    tcp::acceptor acceptor_; \
    bool running_; \
    size_t timeout_; \
    ProtocolGenerator protocol_generator_; \
    std::unordered_map<__session_name *, std::weak_ptr<__session_name>> sessions_; \
}

#define DEFINE_STREAM_SERVER(__server_name, __session_name) \
void __server_name::DoAccept() { \
    acceptor_.async_accept([this](bsys::error_code ec, tcp::socket socket) { \
        if (!ec) { \
            VLOG(1) << "A new client accepted: " << socket.remote_endpoint(); \
            std::shared_ptr<__session_name> session{ \
                new __session_name(std::move(socket), protocol_generator_(), timeout_), \
                std::bind(&__server_name::ReleaseSession, this, std::placeholders::_1) \
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
void __server_name::Stop() { \
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
void __server_name::ReleaseSession(__session_name *ptr) { \
    sessions_.erase(ptr); \
    delete ptr; \
}

struct StreamServerArgs {
    boost::asio::ip::tcp::endpoint bind_ep;
    std::function<std::unique_ptr<BasicProtocol>()> generator;
    size_t timeout;
};

#endif

