
#include <common_utils/socks5.h>

#include "protocol_hooks/shadowsocks.h"

using boost::asio::ip::tcp;

uint8_t ShadowsocksProtocol::ParseHeader(Buffer &buf) {
    uint8_t reply = BasicProtocol::ParseHeader(buf);
    BasicProtocol::need_resolve_ = need_resolve_;
    if (reply != socks5::SUCCEEDED_REP) {
        return reply;
    }
    header_buf_.Append(buf.Size() - 3);
    std::copy(buf.Begin() + 3, buf.End(), header_buf_.Begin());
    return reply;
}

void ShadowsocksProtocol::DoInitializeProtocol(tcp::socket &socket, BasicProtocol::next_stage next) {
    Wrap(header_buf_);
    boost::asio::async_write(
        socket, header_buf_.GetConstBuffer(),
        [next](boost::system::error_code ec, size_t length) {
            if (ec) {
                LOG(INFO) << "unexcepted error while initializing protocol: " << ec;
                return;
            }
            next();
        }
    );
}

