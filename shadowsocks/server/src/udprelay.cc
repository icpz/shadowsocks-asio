
#include "udprelay.h"

#include <common_utils/util.h>

using boost::asio::ip::udp;
namespace bsys = boost::system;

void UdpRelayServer::DoReceive() {
    socket_.async_receive_from(
        boost::asio::buffer(buf_), sender_,
        [this](bsys::error_code ec, size_t length) {
            if (!ec) {
                VLOG(1) << "received from " << sender_;
                ProcessRelay(sender_, length);
            }

            if (running_) {
                DoReceive();
            }
        }
    );
}

void UdpRelayServer::ProcessRelay(udp::endpoint ep, size_t length) {
    auto write_buf = std::make_unique<Buffer>(length);
    write_buf->Append(length);
    std::copy_n(buf_.begin(), length, write_buf->Begin());
    if (crypto_->DecryptOnce(*write_buf) <= 0) {
        LOG(WARNING) << "udp decrypt error";
        return;
    }

    TargetInfo target;
    size_t head_length = GetTargetFromSocks5Address(write_buf->GetData(), nullptr, target);
    if (!head_length) {
        LOG(WARNING) << "invalid udp header";
        return;
    }

    std::shared_ptr<UdpPeer> peer;
    auto itr = targets_.find(ep);
    if (itr == targets_.end()
        || (peer = itr->second.lock()) == nullptr) {
        peer.reset(
            new UdpPeer(socket_.get_executor().context()),
            std::bind(&UdpRelayServer::ReleaseTarget, this, ep, std::placeholders::_1)
        );
        peer->header.reserve(head_length);
        std::copy_n(write_buf->Begin(), head_length, std::back_inserter(peer->header));
        peer->assoc_ep = ep;
        itr = targets_.emplace(ep, peer).first;
    }
    write_buf->DeQueue(head_length);

    peer->timer.cancel();
    if (target.NeedResolve()) {
        auto host = target.GetHostname();
        auto port = std::to_string(target.GetPort());
        DoResolveTarget(std::move(host), std::move(port), peer, std::move(write_buf));
    } else {
        auto remote_ep = udp::endpoint(target.GetIp(), target.GetPort());
        DoConnectTarget(std::move(remote_ep), peer, std::move(write_buf));
    }
}

void UdpRelayServer::DoResolveTarget(
        std::string host, std::string port,
        std::shared_ptr<UdpPeer> peer,
        std::unique_ptr<Buffer> buf
    ) {

    resolver_.async_resolve(
        host, port,
        [this, peer, buf{ std::move(buf) }, host = std::move(host)]
        (bsys::error_code ec, udp::resolver::results_type results) mutable {
            if (ec) {
                LOG(ERROR) << "unable to resolve " << host << ", " << ec.message();
                return;
            }
            DoConnectTarget(*results.begin(), peer, std::move(buf));
        }
    );
}

void UdpRelayServer::DoConnectTarget(
        udp::endpoint ep,
        std::shared_ptr<UdpPeer> peer,
        std::unique_ptr<Buffer> buf
    ) {
    peer->socket.async_connect(
        ep, [this, peer, buf{ std::move(buf) }](bsys::error_code ec) mutable {
            if (ec) {
                LOG(ERROR) << "udp connect error: " << ec.message();
                return;
            }
            DoSendToTarget(peer, std::move(buf));
        }
    );
}

void UdpRelayServer::DoSendToTarget(
        std::shared_ptr<UdpPeer> peer,
        std::unique_ptr<Buffer> buf
    ) {

    auto buffer = buf->GetConstBuffer(); // make sure buf is not moved before get its buffer
    peer->socket.async_send(
        std::move(buffer),
        [this, peer, buf{ std::move(buf) }]
        (bsys::error_code ec, size_t length) {
            if (ec) {
                LOG(WARNING) << "unable to send to target " << peer->socket.remote_endpoint()
                             << ", " << ec.message();
                return;
            }
            TimerAgain(peer);
            DoReceiveFromTarget(peer);
        }
    );
}

void UdpRelayServer::DoReceiveFromTarget(std::shared_ptr<UdpPeer> peer) {
    peer->socket.async_receive(
        peer->buf.GetBuffer(),
        [this, peer](bsys::error_code ec, size_t length) {
            if (ec) {
                if (ec == boost::asio::error::operation_aborted) {
                    VLOG(1) << "operation aborted " << peer->socket.remote_endpoint();
                    return;
                }
                LOG(WARNING) << "unable to receive "
                             << peer->socket.remote_endpoint();
                return;
            }
            peer->timer.cancel();
            peer->buf.Append(length);
            size_t header_length = peer->header.size();
            peer->buf.PrepareCapacity(header_length);
            std::copy_backward(peer->buf.Begin(), peer->buf.End(),
                               peer->buf.End() + header_length);
            std::copy_n(peer->header.begin(), header_length, peer->buf.Begin());
            peer->buf.Append(header_length);

            crypto_->EncryptOnce(peer->buf);
            socket_.async_send_to(
                peer->buf.GetConstBuffer(),
                peer->assoc_ep,
                [this, peer](bsys::error_code ec, size_t length) {
                    if (ec) {
                        LOG(WARNING) << "unable to send to " << peer->assoc_ep
                                     << ", " << ec.message();
                        return;
                    }
                    peer->buf.Reset();
                    TimerAgain(peer);
                    DoReceiveFromTarget(peer);
                }
            );
        }
    );
}

void UdpRelayServer::TimerAgain(std::shared_ptr<UdpPeer> peer) {
    peer->timer.expires_from_now(boost::posix_time::seconds(30));
    peer->timer.async_wait(
        std::bind(
            &UdpRelayServer::TimerExpiredCallback,
            this,
            peer,
            std::placeholders::_1
        )
    );
}

void UdpRelayServer::TimerExpiredCallback(
        std::shared_ptr<UdpPeer> peer,
        bsys::error_code ec
    ) {
    if (ec != boost::asio::error::operation_aborted) {
        peer->socket.cancel();
        VLOG(1) << "timer expired " << peer->socket.remote_endpoint();
    }
}

void UdpRelayServer::ReleaseTarget(udp::endpoint ep, UdpPeer *ptr) {
    auto itr = targets_.find(ep);
    if (itr != targets_.end()) {
        if (itr->second.expired()) {
            targets_.erase(itr);
        }
    }
    delete ptr;
}

void UdpRelayServer::Stop() {
    running_ = false;
    socket_.cancel();
    for (auto &kv : targets_) {
        auto target = kv.second.lock();
        if (target) {
            target->Cancel();
        }
    }
}

