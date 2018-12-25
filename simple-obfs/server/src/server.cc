
#include <utility>

#include <protocol_hooks/basic_stream_session.h>

#include "server.h"

using boost::asio::ip::tcp;
namespace bsys = boost::system;

class Session : public std::enable_shared_from_this<Session>,
                public BasicStreamSession {
public:
    Session(
        tcp::socket socket,
        std::unique_ptr<BasicProtocol> protocol,
        std::shared_ptr<resolver_type> resolver,
        size_t ttl = 5000
    )
        : BasicStreamSession(std::move(socket), std::move(protocol), resolver, ttl) {
    }

    ~Session() {
        VLOG(2) << "Session completed";
    }

    void Start() {
        VLOG(2) << "Session start: " << client_.socket.remote_endpoint();
        auto self(shared_from_this());
        auto after_initialized = [this, self]() {
            auto after_connected = std::bind(&Session::DoWriteToTarget, self);
            if (protocol_->NeedResolve()) {
                std::string hostname;
                uint16_t port;
                protocol_->GetResolveArgs(hostname, port);
                VLOG(1) << "connecting to " << hostname;
                DoResolveTarget(
                    self,
                    std::move(hostname),
                    std::move(port),
                    std::move(after_connected)
                );
            } else {
                auto ep = protocol_->GetEndpoint();
                VLOG(1) << "connecting to " << ep;
                DoConnectTarget(
                    self,
                    std::array<tcp::endpoint, 1>{ ep },
                    std::move(after_connected)
                );
            }
        };

        protocol_->DoInitializeProtocol(
            client_,
            std::move(after_initialized)
        );

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
                    LOG(WARNING) << "Unexcepted write error " << ec.message();
                    return;
                }
                client_.timer.cancel();
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

DEFINE_STREAM_SERVER(ForwardServer, Session);

