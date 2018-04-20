#ifndef __OBFS_PROTO_H__
#define __OBFS_PROTO_H__

#include <protocol_hooks/basic_protocol.h>

#include "obfs_utils/obfs.h"

class ObfsClient : public BasicProtocol {
    typedef boost::asio::ip::tcp tcp;
    using ObfsPointer = std::unique_ptr<Obfuscator>;
public:

    ObfsClient(std::shared_ptr<TargetInfo> remote_info, ObfsPointer obfs)
        : BasicProtocol(std::move(remote_info)),
          obfs_(std::move(obfs)) {
    }

    ~ObfsClient() = default;

    ssize_t Wrap(Buffer &buf) {
        return obfs_->ObfsRequest(buf);
    }

    ssize_t UnWrap(Buffer &buf) {
        return obfs_->DeObfsResponse(buf);
    }

private:
    ObfsPointer obfs_;
};

class ObfsServer : public BasicProtocol {
    typedef boost::asio::ip::tcp tcp;
    using ObfsPointer = std::unique_ptr<Obfuscator>;
    using NextStage = BasicProtocol::NextStage;
public:

    ObfsServer(std::shared_ptr<TargetInfo> remote_info, ObfsPointer obfs)
        : BasicProtocol(std::move(remote_info)),
          obfs_(std::move(obfs)) {
    }

    ~ObfsServer() = default;

    void DoInitializeProtocol(Peer &peer, NextStage next) {
        DoHandshake(peer, std::move(next));
    }

    ssize_t Wrap(Buffer &buf) {
        return obfs_->ObfsResponse(buf);
    }

    ssize_t UnWrap(Buffer &buf) {
        return obfs_->DeObfsRequest(buf);
    }

private:
    void DoHandshake(Peer &peer, NextStage next);

    ObfsPointer obfs_;
};

#endif

