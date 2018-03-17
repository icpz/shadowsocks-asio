
#include <common_utils/socks5.h>
#include <cstdio>

#include "protocol_plugins/shadowsocks.h"

using boost::asio::ip::tcp;

uint8_t ShadowsocksProtocol::ParseHeader(Buffer &buf) {
    uint8_t reply = BasicProtocol::ParseHeader(buf);
    if (reply != socks5::SUCCEEDED_REP) {
        return reply;
    }
    header_buf_.Append(buf.Size() - 3);
    std::copy(buf.Begin() + 3, buf.End(), header_buf_.Begin());
    return reply;
}

void ShadowsocksProtocol::DoInitializeProtocol(tcp::socket &socket, BasicProtocol::next_stage next) {
    fprintf(stderr, "header dump: \n");
    for (int i = 0; i < header_buf_.Size(); ++i) {
        fprintf(stderr, "%02hhx", header_buf_.Begin()[i]);
    }
    fputs("\n", stderr);
    Wrap(header_buf_);
    boost::asio::async_write(
        socket, header_buf_.get_const_buffer(),
        [next](boost::system::error_code ec, size_t length) {
            if (ec) {
                LOG(INFO) << "unexcepted error while initializing protocol: " << ec;
                return;
            }
            next();
        }
    );
}

