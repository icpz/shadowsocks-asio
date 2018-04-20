
#ifndef __BASIC_PROTOCOL_H__
#define __BASIC_PROTOCOL_H__

#include <memory>
#include <utility>
#include <functional>
#include <type_traits>
#include <boost/asio.hpp>

#include <common_utils/util.h>

class BasicProtocol {
    typedef boost::asio::ip::tcp tcp;
protected:
    using NextStage = std::function<void(void)>;

public:
    using Wrapper = std::function<ssize_t(Buffer &)>;

    explicit
    BasicProtocol(std::shared_ptr<TargetInfo> remote_info = nullptr)
        : remote_info_(std::move(remote_info)),
          initialized_(false) {
    }

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
    virtual bool NeedResolve() const { return remote_info_->NeedResolve(); }
    virtual bool HasTarget() const { return !remote_info_->IsEmpty(); }

protected:
    size_t header_length_;
    std::shared_ptr<const TargetInfo> remote_info_;
    bool initialized_;
};

template<typename ProtocolType, typename ...Args>
std::unique_ptr<BasicProtocol>
    GetProtocol(Args&& ...args) {
    static_assert(std::is_base_of<BasicProtocol, ProtocolType>::value, "ProtocolType must inherit from BasicProtocol");
    return std::make_unique<ProtocolType>(std::forward<Args>(args)...);
}

#endif

