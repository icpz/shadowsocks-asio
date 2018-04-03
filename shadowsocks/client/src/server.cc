
#include <utility>
#include <memory>
#include <algorithm>

#include <common_utils/common.h>
#include <common_utils/util.h>
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
        VLOG(2) << "Session start: " << client_.socket.remote_endpoint()
                   << ", reading method selection message";
        DoReadSocks5MethodSelectionMessage();
    }

private:
    void DoReadSocks5MethodSelectionMessage() {
        auto self(shared_from_this());
        client_.socket.async_read_some(
            client_.buf.GetBuffer(),
            [this, self](bsys::error_code ec, size_t len) {
                if (ec) {
                    if (ec == boost::asio::error::misc_errors::eof) {
                        VLOG(2) << "Got EOF";
                        return;
                    }
                    LOG(WARNING) << "Error: " << ec; 
                    return;
                }
                client_.timer.cancel();
                client_.buf.Append(len);
                auto *hdr = (socks5::MethodSelectionMessageHeader *)(client_.buf.GetData());
                if (hdr->ver != socks5::VERSION) {
                    LOG(WARNING) << "Unsupport socks version: " << (uint32_t)hdr->ver;
                    return;
                }
                size_t need_more = socks5::MethodSelectionMessageHeader::NeedMore(
                                        client_.buf.GetData(), client_.buf.Size());
                if (need_more) {
                    VLOG(2) << "need more data, current: " << client_.buf.Size()
                               << "excepted more: " << need_more;
                    client_.buf.PrepareCapacity(need_more);
                    DoReadSocks5MethodSelectionMessage();
                    return;
                }
                uint8_t method_selected = socks5::NO_ACCCEPTABLE_METHOD;
                for (uint8_t i = 0; i < hdr->num_methods; ++i) {
                    if (hdr->methods[i] == socks5::NO_AUTH_METHOD) {
                        method_selected = hdr->methods[i];
                        break;
                    }
                }
                VLOG(2) << "Start write reply";
                DoWriteSocks5MethodSelectionReply(method_selected);
            }
        );
        TimerAgain(self, client_);
    }

    void DoWriteSocks5MethodSelectionReply(uint8_t method) {
        auto self(shared_from_this());
        auto *hdr = (socks5::MethodSelectionMessageReply *)(client_.buf.GetData());
        hdr->ver = socks5::VERSION;
        hdr->method = method;
        client_.buf.Reset(2);
        boost::asio::async_write(
            client_.socket, client_.buf.GetConstBuffer(),
            [this, self, method](bsys::error_code ec, size_t len) {
                if (ec) {
                    LOG(WARNING) << "Unexcepted error: " << ec;
                    return;
                }
                client_.timer.cancel();
                client_.buf.Reset();
                if (method == socks5::NO_AUTH_METHOD) {
                    DoReadSocks5Request();
                }
            }
        );
        TimerAgain(self, client_);
    }

    void DoReadSocks5Request(size_t at_least = 4) {
        auto self(shared_from_this());
        boost::asio::async_read(
            client_.socket,
            client_.buf.GetBuffer(),
            boost::asio::transfer_at_least(at_least),
            [this, self](bsys::error_code ec, size_t len) {
                if (ec) {
                    LOG(WARNING) << "Unexcepted error: " << ec;
                    client_.CancelAll();
                    return;
                }
                client_.timer.cancel();
                client_.buf.Append(len);
                size_t need_more = socks5::Request::NeedMore(client_.buf.GetData(),
                                                             client_.buf.Size());
                if (need_more) {
                    VLOG(2) << "Need more data: " << need_more;
                    client_.buf.PrepareCapacity(need_more);
                    DoReadSocks5Request(need_more);
                    return;
                }
                auto *hdr = (socks5::Request *)(client_.buf.GetData());
                if (hdr->ver != socks5::VERSION) {
                    LOG(WARNING) << "Unsupport socks version: " << (uint32_t)hdr->ver;
                    client_.CancelAll();
                    return;
                }

                if (hdr->cmd != socks5::CONNECT_CMD) {
                    LOG(WARNING) << "Unsupport socks command: " << (uint32_t)hdr->cmd;
                    DoWriteSocks5Reply(socks5::CMD_NOT_SUPPORTED_REP);
                    return;
                }

                uint8_t reply = protocol_->ParseHeader(client_.buf, 3);

                if (reply != socks5::SUCCEEDED_REP) {
                    LOG(WARNING) << "Unsuccessful reply: " << (uint32_t)reply;
                    DoWriteSocks5Reply(reply);
                    return;
                }

                boost::asio::ip::address address;
                if (protocol_->NeedResolve()) {
                    std::string hostname, port;
                    protocol_->GetResolveArgs(hostname, port);
                    DoResolveRemote(std::move(hostname), std::move(port));
                } else {
                    tcp::endpoint ep = protocol_->GetEndpoint();
                    VLOG(2) << "Connecting to " << ep;
                    DoConnectRemote(std::array<tcp::endpoint, 1>{ ep });
                }
            }
        );
        TimerAgain(self, client_);
    }

    void DoResolveRemote(std::string host, std::string port) {
        auto self(shared_from_this());
        VLOG(2) << "Resolving to " << host << ":" << port;
        resolver_.async_resolve(
            host, port,
            [this, self](bsys::error_code ec, tcp::resolver::results_type results) {
                if (ec) {
                    VLOG(1) << "Unable to resolve: " << ec;
                    DoWriteSocks5Reply(socks5::HOST_UNREACHABLE_REP);
                    return;
                }
                DoConnectRemote(std::move(results));
            }
        );
    }

    template<class EndpointSequence>
    void DoConnectRemote(const EndpointSequence &results) {
        auto self(shared_from_this());
        boost::asio::async_connect(
            target_.socket, results,
            [this, self](bsys::error_code ec, tcp::endpoint ep) {
                if (ec) {
                    if (ec == boost::asio::error::operation_aborted) {
                        VLOG(1) << "Connect canceled";
                        return;
                    }
                    LOG(INFO) << "Cannot connect to remote: " << ec;
                    DoWriteSocks5Reply((ec == boost::asio::error::connection_refused
                                        ? socks5::CONN_REFUSED_REP
                                        : socks5::NETWORK_UNREACHABLE_REP));
                    return;
                }
                client_.timer.cancel();
                VLOG(1) << "Connected to remote " << ep;
                DoWriteSocks5Reply(socks5::SUCCEEDED_REP);
            }
        );
        TimerAgain(self, client_);
    }

    void DoWriteSocks5Reply(uint8_t reply) {
        auto self(shared_from_this());
        auto *hdr = (socks5::Reply *)(client_.buf.GetData());
        hdr->rsv = 0;
        hdr->rep = reply;
        client_.buf.Reset(
                socks5::Reply::FillBoundAddress(client_.buf.GetData(),
                                                target_.socket.local_endpoint()));
        boost::asio::async_write(
            client_.socket,
            client_.buf.GetConstBuffer(),
            [this, self, reply](bsys::error_code ec, size_t len) {
                if (ec) {
                    LOG(WARNING) << "Unexcepted write error " << ec;
                    return;
                }
                if (reply == socks5::SUCCEEDED_REP) {
                    VLOG(2) << "Start streaming";
                    client_.timer.cancel();
                    client_.buf.Reset();
                    protocol_->DoInitializeProtocol(
                        target_,
                        std::bind(&Session::StartStream, self)
                    );
                } else {
                    client_.CancelAll();
                }
            }
        );
        TimerAgain(self, client_);
    }

    void StartStream() {
        auto self(shared_from_this());
        DoRelayStream(self, client_, target_,
                      std::bind(&BasicProtocol::Wrap,
                                std::ref(protocol_),
                                std::placeholders::_1));
        DoRelayStream(self, target_, client_,
                      std::bind(&BasicProtocol::UnWrap,
                                std::ref(protocol_),
                                std::placeholders::_1));
    }

};

DEFINE_STREAM_SERVER(Socks5ProxyServer, Session);

