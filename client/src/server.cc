
#include <utility>
#include <memory>
#include <algorithm>
#include <boost/log/trivial.hpp>
#include <boost/endian/conversion.hpp>

#include <common_utils/common.h>
#include <common_utils/util.h>

#include "server.h"

using boost::asio::ip::tcp;
namespace bsys = boost::system;

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket socket, std::unique_ptr<BasicProtocol> protocol, size_t ttl = 5000)
        : context_(socket.get_executor().context()),
          client_(std::move(socket), ttl), remote_(context_, ttl),
          resolver_(context_), protocol_(std::move(protocol)) {
    }

    ~Session() {
        LOG(TRACE) << "Session completed";
    }

    void Start() {
        LOG(TRACE) << "Session start: " << client_.socket.remote_endpoint()
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
                        LOG(TRACE) << "Got EOF";
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
                    LOG(TRACE) << "need more data, current: " << client_.buf.Size()
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
                LOG(TRACE) << "Start write reply";
                DoWriteSocks5MethodSelectionReply(method_selected);
            }
        );
        TimerAgain(client_);
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
        TimerAgain(client_);
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
                    LOG(TRACE) << "Need more data: " << need_more;
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
                    LOG(TRACE) << "Resolving to " << hostname << ":" << port;
                    DoResolveRemote(std::move(hostname), std::move(port));
                } else {
                    tcp::endpoint ep = protocol_->GetEndpoint();
                    LOG(TRACE) << "Connecting to " << ep;
                    DoConnectRemote(ep);
                }
            }
        );
        TimerAgain(client_);
    }

    void DoResolveRemote(std::string host, std::string port) {
        auto self(shared_from_this());
        resolver_.async_resolve(host, port,
            [this, self](bsys::error_code ec, tcp::resolver::iterator itr) {
                if (ec) {
                    LOG(DEBUG) << "Unable to resolve: " << ec;
                    DoWriteSocks5Reply(socks5::HOST_UNREACHABLE_REP);
                    return;
                }
                DoConnectRemote(itr);
            }
        );
    }

    void DoConnectRemote(tcp::resolver::iterator itr) {
        auto self(shared_from_this());
        boost::asio::async_connect(remote_.socket, itr,
            [this, self](bsys::error_code ec, tcp::resolver::iterator itr) {
                if (ec || itr == tcp::resolver::iterator()) {
                    LOG(DEBUG) << "Cannot connect to remote: " << ec;
                    DoWriteSocks5Reply((itr == tcp::resolver::iterator()
                                        ? socks5::CONN_REFUSED_REP
                                        : socks5::NETWORK_UNREACHABLE_REP));
                    return;
                }
                LOG(DEBUG) << "Connected to remote " << itr->host_name();
                client_.timer.cancel();
                DoWriteSocks5Reply(socks5::SUCCEEDED_REP);
            }
        );
        TimerAgain(client_);
    }

    void DoConnectRemote(tcp::endpoint ep) {
        auto self(shared_from_this());
        boost::asio::async_connect(remote_.socket, std::array<tcp::endpoint, 1>{ ep },
            [this, self](bsys::error_code ec, tcp::endpoint ep) {
                if (ec) {
                    if (ec == boost::asio::error::operation_aborted) {
                        LOG(DEBUG) << "Connect canceled";
                        return;
                    }
                    LOG(INFO) << "Cannot connect to remote: " << ec;
                    DoWriteSocks5Reply((ec == boost::asio::error::connection_refused
                                        ? socks5::CONN_REFUSED_REP
                                        : socks5::NETWORK_UNREACHABLE_REP));
                    return;
                }
                client_.timer.cancel();
                LOG(DEBUG) << "Connected to remote " << ep;
                DoWriteSocks5Reply(socks5::SUCCEEDED_REP);
            }
        );
        TimerAgain(client_);
    }

    void DoWriteSocks5Reply(uint8_t reply) {
        auto self(shared_from_this());
        auto *hdr = (socks5::Reply *)(client_.buf.GetData());
        hdr->rsv = 0;
        hdr->rep = reply;
        client_.buf.Reset(
                socks5::Reply::FillBoundAddress(client_.buf.GetData(),
                                                remote_.socket.local_endpoint()));
        boost::asio::async_write(client_.socket, client_.buf.GetConstBuffer(),
            [this, self, reply](bsys::error_code ec, size_t len) {
                if (ec) {
                    LOG(WARNING) << "Unexcepted write error " << ec;
                    return;
                }
                if (reply == socks5::SUCCEEDED_REP) {
                    LOG(TRACE) << "Start streaming";
                    client_.timer.cancel();
                    client_.buf.Reset();
                    protocol_->DoInitializeProtocol(
                        remote_,
                        std::bind(&Session::StartStream, self)
                    );
                } else {
                    client_.CancelAll();
                }
            }
        );
        TimerAgain(client_);
    }

    void StartStream() {
        DoRelayStream(client_, remote_,
                      std::bind(&BasicProtocol::Wrap,
                                std::ref(protocol_),
                                std::placeholders::_1));
        DoRelayStream(remote_, client_,
                      std::bind(&BasicProtocol::UnWrap,
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
            LOG(DEBUG) << peer.socket.remote_endpoint() << " TTL expired";
            client_.CancelAll();
            remote_.CancelAll();
            client_.socket.close();
            remote_.socket.close();
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
    Peer remote_;
    tcp::resolver resolver_;
    std::unique_ptr<BasicProtocol> protocol_;
};

void Socks5ProxyServer::DoAccept() {
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

