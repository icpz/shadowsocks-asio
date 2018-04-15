
#ifndef __CLIENT_H__
#define __CLIENT_H__

#include <memory>
#include <boost/asio.hpp>

#include <common_utils/util.h>
#include <crypto_utils/cipher.h>

#include "protocol_hooks/basic_protocol.h"

class ShadowsocksClient : public BasicProtocol {
    typedef boost::asio::ip::tcp tcp;
    using CryptoContextPtr = std::unique_ptr<CryptoContext>;
    using NextStage = BasicProtocol::NextStage;
public:
    ShadowsocksClient(std::shared_ptr<TargetInfo> remote_info, CryptoContextPtr crypto_context)
        : header_buf_(300UL),
          remote_info_(std::move(remote_info)),
          crypto_context_(std::move(crypto_context)) {
    }

    ~ShadowsocksClient() { }

    uint8_t ParseHeader(Buffer &buf, size_t start_offset);
    ssize_t Wrap(Buffer &buf) {
        return crypto_context_->Encrypt(buf);
    }

    ssize_t UnWrap(Buffer &buf) {
        return crypto_context_->Decrypt(buf);
    }

    void DoInitializeProtocol(Peer &peer, NextStage next);

    tcp::endpoint GetEndpoint() const {
        return tcp::endpoint(remote_info_->GetIp(), remote_info_->GetPort());
    }

    bool GetResolveArgs(std::string &hostname, std::string &port) const {
        if (!NeedResolve()) return false;
        hostname = remote_info_->GetHostname();
        port = std::to_string(remote_info_->GetPort());
        return true;
    }

    bool NeedResolve() const {
        return remote_info_->NeedResolve();
    }

private:
    Buffer header_buf_;
    std::shared_ptr<const TargetInfo> remote_info_;
    CryptoContextPtr crypto_context_;
};

#endif

