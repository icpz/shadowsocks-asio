
#ifndef __SHADOWSOCKS_H__
#define __SHADOWSOCKS_H__

#include <memory>
#include <crypto_utils/cipher.h>

#include "protocol_plugins/basic_protocol.h"

class ShadowsocksProtocol : public BasicProtocol {
    typedef boost::asio::ip::tcp tcp;
    using CryptoContextPtr = std::unique_ptr<CryptoContext>;
    using CryptoContextGenerator = std::function<CryptoContextPtr(void)>;
public:
    ShadowsocksProtocol(tcp::endpoint ep, CryptoContextGenerator generator)
        : header_buf_(300UL),
          remote_endpoint_(std::move(ep)),
          crypto_context_(generator()) {
    }

    ShadowsocksProtocol(std::string host, uint16_t port, CryptoContextGenerator generator)
        : header_buf_(300UL),
          remote_host_(std::move(host)),
          remote_port_(std::to_string(port)),
          crypto_context_(generator()) {
        need_resolve_ = true;
    }

    ~ShadowsocksProtocol() { }

    uint8_t ParseHeader(Buffer &buf);
    ssize_t Wrap(Buffer &buf) {
        return crypto_context_->Encrypt(buf);
    }

    ssize_t UnWrap(Buffer &buf) {
        return crypto_context_->Decrypt(buf);
    }

    void DoInitializeProtocol(tcp::socket &socket, BasicProtocol::next_stage next);

    tcp::endpoint GetEndpoint() const { return remote_endpoint_; }
    bool GetResolveArgs(std::string &hostname, std::string &port) const {
        if (!NeedResolve()) return false;
        hostname = remote_host_;
        port = remote_port_;
        return true;
    }

private:
    Buffer header_buf_;
    tcp::endpoint remote_endpoint_;
    std::string remote_host_;
    std::string remote_port_;
    CryptoContextPtr crypto_context_;
};

#endif

