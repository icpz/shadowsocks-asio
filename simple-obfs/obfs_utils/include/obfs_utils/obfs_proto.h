#ifndef __OBFS_PROTO_H__
#define __OBFS_PROTO_H__

#include <protocol_hooks/basic_protocol.h>

#include "obfs_utils/obfs.h"

class ObfsClient : public BasicProtocol {
    typedef boost::asio::ip::tcp tcp;
    using ObfsPointer = std::unique_ptr<Obfuscator>;
public:

    ObfsClient(tcp::endpoint ep, ObfsPointer obfs)
        : obfs_(std::move(obfs)) {
        target_.SetTarget(ep.address(), ep.port());
    }

    ObfsClient(std::string host, uint16_t port, ObfsPointer obfs)
        : obfs_(std::move(obfs)) {
        target_.SetTarget(host, port);
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

#endif

