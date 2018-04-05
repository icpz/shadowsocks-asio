#ifndef __UDPRELAY_H__
#define __UDPRELAY_H__

#include <unordered_map>
#include <boost/asio.hpp>
#include <boost/functional/hash.hpp>

#include <common_utils/buffer.h>
#include <crypto_utils/cipher.h>

namespace std {

template<> struct hash<boost::asio::ip::udp::endpoint> {
    typedef boost::asio::ip::udp::endpoint argument_type;
    typedef size_t result_type;

    result_type operator()(const argument_type &arg) const noexcept {
        return  boost::hash_range(
                    (const uint8_t *)arg.data(),
                    (const uint8_t *)arg.data() + arg.size()
                );
    }
};

}

struct UdpServerParam {
    boost::asio::ip::udp::endpoint bind_ep;
    std::unique_ptr<CryptoContext> crypto;
    bool udp_only = false;
    bool udp_enable = false;
};

class UdpRelayServer : public std::enable_shared_from_this<UdpRelayServer> {
    typedef boost::asio::ip::udp udp;

    struct UdpPeer {
        UdpPeer(boost::asio::io_context &ctx)
            : socket(ctx), timer(ctx) {
        }

        void Cancel() {
            if (socket.is_open()) {
                socket.cancel();
            }
            timer.cancel();
        }

        udp::socket socket;
        udp::endpoint assoc_ep;
        Buffer buf;
        std::vector<uint8_t> header;
        boost::asio::deadline_timer timer;
    };
public:

    UdpRelayServer(boost::asio::io_context &ctx, udp::endpoint ep,
                   std::unique_ptr<CryptoContext> crypto)
        : socket_(ctx, std::move(ep)),
          resolver_(ctx),
          crypto_(std::move(crypto)) {
        running_ = true;
        LOG(INFO) << "running at " << ep;
        DoReceive();
    }

    void Stop();

    bool Stopped() const {
        return !running_;
    }

private:

    void DoReceive();
    void ProcessRelay(udp::endpoint ep, size_t length);
    void DoResolveTarget(std::string host, std::string port,
                         std::shared_ptr<UdpPeer> peer, std::unique_ptr<Buffer> buf);
    void DoConnectTarget(udp::endpoint ep,
                         std::shared_ptr<UdpPeer> peer, std::unique_ptr<Buffer> buf);
    void DoSendToTarget(std::shared_ptr<UdpPeer> peer, std::unique_ptr<Buffer> buf);
    void DoReceiveFromTarget(std::shared_ptr<UdpPeer> peer);

    void TimerExpiredCallback(std::shared_ptr<UdpPeer> peer, boost::system::error_code ec);
    void TimerAgain(std::shared_ptr<UdpPeer> peer);

    static void ReleaseTarget(std::weak_ptr<UdpRelayServer>, udp::endpoint, UdpPeer *);

    bool running_;
    std::array<uint8_t, 8192> buf_;
    udp::socket socket_;
    udp::endpoint sender_;
    udp::resolver resolver_;
    std::unique_ptr<CryptoContext> crypto_;
    std::unordered_map<udp::endpoint, std::weak_ptr<UdpPeer>> targets_;
};

#endif

