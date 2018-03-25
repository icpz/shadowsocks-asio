
#include <utility>
#include <boost/asio.hpp>

#include <common_utils/common.h>
#include <common_utils/socks5.h>
#include <common_utils/buffer.h>

#include "server.h"

using boost::asio::ip::tcp;
namespace bsys = boost::system;

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket socket, std::unique_ptr<BasicProtocol> protocol, size_t ttl = 5000)
        : context_(socket.get_executor().context()),
          client_(std::move(socket), ttl), target_(context_, ttl),
          resolver_(context_), protocol_(std::move(protocol)) {
    }

    ~Session() {
        LOG(TRACE) << "Session completed";
    }

    void Start() {
        LOG(TRACE) << "Session start: " << client_.socket.remote_endpoint();
        auto self(shared_from_this());
        protocol_->DoInitializeProtocol(
            client_,
            [this, self]() {
                if (protocol_->NeedResolve()) {
                    std::string hostname, port;
                    protocol_->GetResolveArgs(hostname, port);
                    DoResolveTarget(std::move(hostname), std::move(port));
                } else {
                    DoConnectTarget(std::array<tcp::endpoint, 1>{ protocol_->GetEndpoint() });
                }
            }
        );
    }

private:

    void DoResolveTarget(std::string host, std::string port) {
        auto self(shared_from_this());
        LOG(TRACE) << "Resolving to " << host << ":" << port;
        resolver_.async_resolve(
            host, port,
            [this, self](bsys::error_code ec, tcp::resolver::results_type results) {
                if (ec) {
                    LOG(DEBUG) << "Unable to resolve: " << ec;
                    client_.CancelAll();
                    return;
                }
                DoConnectTarget(std::move(results));
            }
        );
    }

    template<class EndpointSequence>
    void DoConnectTarget(const EndpointSequence &results) {
        auto self(shared_from_this());
        boost::asio::async_connect(
            target_.socket, results,
            [this, self](bsys::error_code ec, tcp::endpoint ep) {
                if (ec) {
                    if (ec == boost::asio::error::operation_aborted) {
                        LOG(DEBUG) << "Connect canceled";
                        return;
                    }
                    LOG(INFO) << "Cannot connect to remote: " << ec;
                    client_.CancelAll();
                    return;
                }
                client_.timer.cancel();
                LOG(DEBUG) << "Connected to remote " << ep;
                DoWriteToTarget();
            }
        );
        TimerAgain(client_);
    }

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
        TimerAgain(client_);
    }

    void StartStream() {
        DoRelayStream(client_, target_,
                      std::bind(&BasicProtocol::UnWrap,
                                std::ref(protocol_),
                                std::placeholders::_1));
        DoRelayStream(target_, client_,
                      std::bind(&BasicProtocol::Wrap,
                                std::ref(protocol_),
                                std::placeholders::_1));
    }

    void DoRelayStream(Peer &src, Peer &dest, BasicProtocol::Wrapper wrapper) {
        auto self(shared_from_this());
        src.socket.async_read_some(
            src.buf.GetBuffer(),
            [this, self, &src, &dest,
             wrapper = std::move(wrapper)](bsys::error_code ec, size_t len) {
                if (ec) {
                    if (ec == boost::asio::error::misc_errors::eof) {
                        LOG(TRACE) << "Stream terminates normally";
                        src.CancelAll();
                        dest.CancelAll();
                        return;
                    } else if (ec == boost::asio::error::operation_aborted) {
                        LOG(DEBUG) << "Read operation canceled";
                        return;
                    }
                    LOG(WARNING) << "Relay read unexcepted error: " << ec;
                    src.CancelAll();
                    dest.CancelAll();
                    return;
                }
                src.timer.cancel();
                src.buf.Append(len);
                ssize_t valid_length = wrapper(src.buf);
                if (valid_length == 0) { // need more
                    DoRelayStream(src, dest, std::move(wrapper));
                    return;
                } else if (valid_length < 0) { // error occurs
                    LOG(WARNING) << "Protocol hook error";
                    src.CancelAll();
                    dest.CancelAll();
                    return;
                }
                boost::asio::async_write(dest.socket,
                    src.buf.GetConstBuffer(),
                    [this, self,
                     &src, &dest,
                     valid_length,
                     wrapper = std::move(wrapper)](bsys::error_code ec, size_t len) {
                        if (ec) {
                            if (ec == boost::asio::error::operation_aborted) {
                                LOG(DEBUG) << "Write operation canceled";
                                return;
                            }
                            LOG(WARNING) << "Relay write unexcepted error: " << ec;
                            src.CancelAll();
                            dest.CancelAll();
                            return;
                        }
                        dest.timer.cancel();
                        src.buf.Reset();
                        DoRelayStream(src, dest, std::move(wrapper));
                        TimerAgain(src);
                    }
                );
                TimerAgain(dest);
            }
        );
    }

    void TimerExpiredCallBack(Peer &peer, bsys::error_code ec) {
        if (ec != boost::asio::error::operation_aborted) {
            if (peer.socket.is_open()) {
                LOG(DEBUG) << peer.socket.remote_endpoint() << " TTL expired";
            } else {
                LOG(WARNING) << "timer of closed socket expired!";
            }
            client_.CancelAll();
            target_.CancelAll();
            client_.socket.close();
            target_.socket.close();
        }
    }

    void TimerAgain(Peer &peer) {
        auto self(shared_from_this());
        peer.timer.expires_from_now(peer.ttl);
        peer.timer.async_wait(
            std::bind(&Session::TimerExpiredCallBack,
                      self, std::ref(peer),
                      std::placeholders::_1
            )
        );
    }

    boost::asio::io_context &context_;
    Peer client_;
    Peer target_;
    tcp::resolver resolver_;
    std::unique_ptr<BasicProtocol> protocol_;
};

void ForwardServer::DoAccept() {
    acceptor_.async_accept([this](bsys::error_code ec, tcp::socket socket) {
        if (!ec) {
            LOG(INFO) << "A new client accepted: " << socket.remote_endpoint();
            std::make_shared<Session>(std::move(socket), protocol_generator_())->Start();
        }
        if (running_) {
            DoAccept();
        }
    });
}

