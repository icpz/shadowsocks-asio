
#include <boost/endian/arithmetic.hpp>
#include <common_utils/socks5.h>

#include "ss_proto/tunnel.h"

using boost::asio::ip::tcp;

std::vector<uint8_t> ShadowsocksTunnel::kHeaderBuf;

void ShadowsocksTunnel::InitializeTunnel(const TargetInfo &forward_target) {
    if (forward_target.NeedResolve()) {
        auto hostname = forward_target.GetHostname();
        kHeaderBuf.push_back(socks5::DOMAIN_ATYPE);
        kHeaderBuf.push_back((uint8_t)hostname.size());
        kHeaderBuf.insert(kHeaderBuf.end(), hostname.begin(), hostname.end());
    } else {
        auto address = forward_target.GetIp();
        if (address.is_v4()) {
            auto v4_bytes = address.to_v4().to_bytes();
            kHeaderBuf.push_back(socks5::IPV4_ATYPE);
            kHeaderBuf.insert(kHeaderBuf.end(), v4_bytes.begin(), v4_bytes.end());
        } else {
            auto v6_bytes = address.to_v6().to_bytes();
            kHeaderBuf.push_back(socks5::IPV6_ATYPE);
            kHeaderBuf.insert(kHeaderBuf.end(), v6_bytes.begin(), v6_bytes.end());
        }
    }
    boost::endian::big_uint16_buf_t port_buf{ forward_target.GetPort() };
    kHeaderBuf.insert(kHeaderBuf.end(), (uint8_t *)&port_buf, (uint8_t *)&port_buf + 2);;
}

void ShadowsocksTunnel::DoInitializeProtocol(Peer &peer, BasicProtocol::NextStage next) {
    peer.buf.AppendData(kHeaderBuf);
    Wrap(peer.buf);
    next();
}

