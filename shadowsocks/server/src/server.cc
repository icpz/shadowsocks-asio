
#include <utility>
#include <boost/asio.hpp>

#include <common_utils/common.h>
#include <common_utils/socks5.h>
#include <common_utils/buffer.h>
#include <protocol_hooks/basic_stream_session.h>

#include "server.h"

using boost::asio::ip::tcp;
namespace bsys = boost::system;

class Session : public std::enable_shared_from_this<Session>,
                public BasicStreamSession {
public:
    Session(tcp::socket socket, std::unique_ptr<BasicProtocol> protocol, size_t ttl = 5000)
        : BasicStreamSession(std::move(socket), std::move(protocol), ttl) {
    }

    ~Session() {
        VLOG(2) << "Session completed";
    }

    void Start() {
        VLOG(2) << "Session start: " << client_.socket.remote_endpoint();
        auto self(shared_from_this());
        protocol_->DoInitializeProtocol(
            client_,
            [this, self]() {
                auto after_connected = std::bind(&Session::DoWriteToTarget, self);
                if (protocol_->NeedResolve()) {
                    std::string hostname, port;
                    protocol_->GetResolveArgs(hostname, port);
                    DoResolveTarget(
                        self,
                        std::move(hostname),
                        std::move(port),
                        std::move(after_connected)
                    );
                } else {
                    DoConnectTarget(
                        self,
                        std::array<tcp::endpoint, 1>{ protocol_->GetEndpoint() },
                        std::move(after_connected)
                    );
                }
            }
        );
    }

    void Close() {
        VLOG(1) << "Closing: " << client_.socket.remote_endpoint();
        client_.CancelAll();
        target_.CancelAll();
    }

private:
    void DoWriteToTarget() {
        if (!client_.buf.Size()) {
            StartStream();
            return;
        }
        auto self(shared_from_this());

        boost::asio::async_write(
            target_.socket,
            client_.buf.GetConstBuffer(),
            [this, self](bsys::error_code ec, size_t len) {
                if (ec) {
                    LOG(WARNING) << "Unexcepted write error " << ec;
                    return;
                }
                client_.buf.Reset();
                StartStream();
            }
        );
        TimerAgain(self, client_);
    }

    void StartStream() {
        auto self(shared_from_this());
        DoRelayStream(self, client_, target_,
                      std::bind(&BasicProtocol::UnWrap,
                                std::ref(protocol_),
                                std::placeholders::_1));
        DoRelayStream(self, target_, client_,
                      std::bind(&BasicProtocol::Wrap,
                                std::ref(protocol_),
                                std::placeholders::_1));
    }

};

void ForwardServer::DoAccept() {
    acceptor_.async_accept([this](bsys::error_code ec, tcp::socket socket) {
        if (!ec) {
            VLOG(1) << "A new client accepted: " << socket.remote_endpoint();
            std::shared_ptr<Session> session{
                new Session(std::move(socket), protocol_generator_()),
                std::bind(&ForwardServer::ReleaseSession, this, std::placeholders::_1)
            };
            sessions_.emplace(session.get(), session);
            session->Start();
        }
        if (running_) {
            DoAccept();
        }
    });
}

void ForwardServer::Stop() {
    acceptor_.cancel();
    running_ = false;
    for (auto &kv : sessions_) {
        auto p = kv.second.lock();
        if (p) {
            p->Close();
        }
    }
}

void ForwardServer::ReleaseSession(Session *ptr) {
    sessions_.erase(ptr);
    delete ptr;
}

