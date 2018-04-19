#ifndef __OBFS_PROTO_H__
#define __OBFS_PROTO_H__

#include <protocol_hooks/basic_protocol.h>

#include "obfs_utils/obfs.h"

class ObfsClient : public BasicProtocol {
    typedef boost::asio::ip::tcp tcp;
    using ObfsPointer = std::unique_ptr<Obfuscator>;
public:

    ObfsClient(std::shared_ptr<TargetInfo> remote_info, ObfsPointer obfs)
        : obfs_(std::move(obfs)),
          remote_info_(std::move(remote_info)) {
    }

    ~ObfsClient() = default;

    ssize_t Wrap(Buffer &buf) {
        return obfs_->ObfsRequest(buf);
    }

    ssize_t UnWrap(Buffer &buf) {
        return obfs_->DeObfsResponse(buf);
    }

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
    ObfsPointer obfs_;
    std::shared_ptr<const TargetInfo> remote_info_;
};

class ObfsServer : public BasicProtocol {
    typedef boost::asio::ip::tcp tcp;
    using ObfsPointer = std::unique_ptr<Obfuscator>;
    using NextStage = BasicProtocol::NextStage;
public:

    ObfsServer(std::shared_ptr<TargetInfo> remote_info, ObfsPointer obfs)
        : obfs_(std::move(obfs)),
          remote_info_(std::move(remote_info)) {
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
    void DoHandshake(Peer &peer, NextStage next);

    ObfsPointer obfs_;
    std::shared_ptr<const TargetInfo> remote_info_;
};

#endif

