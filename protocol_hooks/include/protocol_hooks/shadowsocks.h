
#ifndef __SHADOWSOCKS_H__
#define __SHADOWSOCKS_H__

#include <memory>
#include <boost/asio.hpp>

#include <common_utils/util.h>
#include <crypto_utils/cipher.h>

#include "protocol_hooks/basic_protocol.h"

class ShadowsocksClient : public BasicProtocol {
    typedef boost::asio::ip::tcp tcp;
    using CryptoContextPtr = std::unique_ptr<CryptoContext>;
public:
    ShadowsocksClient(tcp::endpoint ep, CryptoContextPtr crypto_context)
        : header_buf_(300UL),
          remote_endpoint_(std::move(ep)),
          crypto_context_(std::move(crypto_context)) {
        need_resolve_ = false;
    }

    ShadowsocksClient(std::string host, uint16_t port, CryptoContextPtr crypto_context)
        : header_buf_(300UL),
          remote_host_(std::move(host)),
          remote_port_(std::to_string(port)),
          crypto_context_(std::move(crypto_context)) {
        need_resolve_ = true;
    }

    ~ShadowsocksClient() { }

    uint8_t ParseHeader(Buffer &buf, size_t start_offset);
    ssize_t Wrap(Buffer &buf) {
        return crypto_context_->Encrypt(buf);
    }

    ssize_t UnWrap(Buffer &buf) {
        return crypto_context_->Decrypt(buf);
    }

    void DoInitializeProtocol(Peer &peer, BasicProtocol::NextStage next);

    tcp::endpoint GetEndpoint() const { return remote_endpoint_; }
    bool GetResolveArgs(std::string &hostname, std::string &port) const {
        if (!NeedResolve()) return false;
        hostname = remote_host_;
        port = remote_port_;
        return true;
    }

    bool NeedResolve() const {
        return need_resolve_;
    }

private:
    bool need_resolve_;
    Buffer header_buf_;
    tcp::endpoint remote_endpoint_;
    std::string remote_host_;
    std::string remote_port_;
    CryptoContextPtr crypto_context_;
};

class ShadowsocksServer : public BasicProtocol {
    typedef boost::asio::ip::tcp tcp;
    using CryptoContextPtr = std::unique_ptr<CryptoContext>;
    using NextStage = BasicProtocol::NextStage;
public:
    ShadowsocksServer(CryptoContextPtr crypto_context)
        : crypto_context_(std::move(crypto_context)) { }

    ~ShadowsocksServer() { }

    void DoInitializeProtocol(Peer &peer, NextStage next) {
        DoReadHeader(peer, std::move(next));
    }

    ssize_t Wrap(Buffer &buf) {
        return crypto_context_->Encrypt(buf);
    }

    ssize_t UnWrap(Buffer &buf) {
        return crypto_context_->Decrypt(buf);
    }

private:
    void DoReadHeader(Peer &peer, NextStage next, size_t at_least = 4);

    Buffer header_buf_;
    CryptoContextPtr crypto_context_;
};

#endif

