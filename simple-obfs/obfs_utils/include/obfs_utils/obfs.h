#ifndef __OBFS_H__
#define __OBFS_H__

#include <common_utils/buffer.h>
#include <protocol_hooks/basic_protocol.h>

class Obfuscator : public BasicProtocol {
    typedef boost::asio::ip::tcp tcp;
public:

    Obfuscator(tcp::endpoint ep) {
        target_.SetTarget(ep.address(), ep.port());
    }

    Obfuscator(std::string host, uint16_t port) {
        target_.SetTarget(std::move(host), port);
    }

    virtual ~Obfuscator() = default;

    virtual ssize_t Wrap(Buffer &buf) {
        return Obfs(buf);
    }

    virtual ssize_t UnWrap(Buffer &buf) {
        return DeObfs(buf);
    }

    virtual ssize_t Obfs(Buffer &buf) = 0;
    virtual ssize_t DeObfs(Buffer &buf) = 0;

protected:
    bool initialized_ = false;
};

#endif

