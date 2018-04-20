
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
        : BasicProtocol(std::move(remote_info)),
          header_buf_(300UL),
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

private:
    Buffer header_buf_;
    CryptoContextPtr crypto_context_;
};

#endif

