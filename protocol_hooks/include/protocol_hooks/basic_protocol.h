
#ifndef __BASIC_PROTOCOL_H__
#define __BASIC_PROTOCOL_H__

#include <memory>
#include <utility>
#include <functional>
#include <type_traits>
#include <boost/asio.hpp>
#include <boost/variant.hpp>

#include <common_utils/util.h>

class TargetInfo {
public:
    using IpAddress = boost::asio::ip::address;
    bool NeedResolve() const {
        return state_ == 2;
    }

    bool IsEmpty() const {
        return state_ == 0;
    }

    void SetTarget(IpAddress ip, uint16_t port) {
        address_ = std::move(ip);
        port_ = port;
        state_ = 1;
    }

    void SetTarget(std::string host, uint16_t port) {
        address_ = std::move(host);
        port_ = port;
        state_ = 2;
    }

    std::string GetHostname() const {
        return boost::get<std::string>(address_);
    }

    IpAddress GetIp() const {
        return boost::get<IpAddress>(address_);
    }

    uint16_t GetPort() const {
        return port_;
    }

private:
    uint32_t state_ = 0;
    boost::variant<IpAddress, std::string> address_;
    uint16_t port_;
};

class BasicProtocol {
    typedef boost::asio::ip::tcp tcp;
protected:
    using NextStage = std::function<void(void)>;

public:
    using Wrapper = std::function<ssize_t(Buffer &)>;

    BasicProtocol() : initialized_(false) { }
    virtual ~BasicProtocol() { }

    virtual uint8_t ParseHeader(Buffer &buf, size_t start_offset);
    virtual ssize_t Wrap(Buffer &buf) { return buf.Size(); }
    virtual ssize_t UnWrap(Buffer &buf) { return buf.Size(); }
    virtual void DoInitializeProtocol(Peer &peer, NextStage next) {
        initialized_ = true;
        next();
    }
    virtual tcp::endpoint GetEndpoint() const;
    virtual bool GetResolveArgs(std::string &hostname, std::string &port) const;
    virtual bool NeedResolve() const { return target_.NeedResolve(); }
    virtual bool HasTarget() const { return !target_.IsEmpty(); }

protected:
    size_t header_length_;
    TargetInfo target_;
    bool initialized_;
};

template<typename ProtocolType, typename ...Args>
std::unique_ptr<BasicProtocol>
    GetProtocol(Args&& ...args) {
    static_assert(std::is_base_of<BasicProtocol, ProtocolType>::value, "ProtocolType must inherit from BasicProtocol");
    return std::make_unique<ProtocolType>(std::forward<Args>(args)...);
}

#endif

