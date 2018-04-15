
#ifndef __SERVER_H__
#define __SERVER_H__

#include <memory>
#include <boost/asio.hpp>

#include <common_utils/util.h>
#include <crypto_utils/cipher.h>

#include "protocol_hooks/basic_protocol.h"

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

