
#ifndef __TUNNEL_H__
#define __TUNNEL_H__

#include <memory>
#include <boost/asio.hpp>

#include <common_utils/util.h>
#include <crypto_utils/cipher.h>

#include "protocol_hooks/basic_protocol.h"

class ShadowsocksTunnel : public BasicProtocol {
    typedef boost::asio::ip::tcp tcp;
    using CryptoContextPtr = std::unique_ptr<CryptoContext>;
    using NextStage = BasicProtocol::NextStage;
public:
    ShadowsocksTunnel(std::shared_ptr<TargetInfo> remote_info, CryptoContextPtr crypto_context)
        : BasicProtocol(std::move(remote_info)),
          crypto_context_(std::move(crypto_context)) {
    }

    ~ShadowsocksTunnel() { }

    ssize_t Wrap(Buffer &buf) {
        return crypto_context_->Encrypt(buf);
    }

    ssize_t UnWrap(Buffer &buf) {
        return crypto_context_->Decrypt(buf);
    }

    void DoInitializeProtocol(Peer &peer, NextStage next);

    static void InitializeTunnel(const TargetInfo &forward_target);
private:
    static std::vector<uint8_t> kHeaderBuf;

    CryptoContextPtr crypto_context_;
};

#endif

