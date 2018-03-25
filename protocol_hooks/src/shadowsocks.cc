
#include <common_utils/socks5.h>

#include "protocol_hooks/shadowsocks.h"

using boost::asio::ip::tcp;

uint8_t ShadowsocksClient::ParseHeader(Buffer &buf, size_t start_offset) {
    uint8_t reply = BasicProtocol::ParseHeader(buf, start_offset);
    if (reply != socks5::SUCCEEDED_REP) {
        return reply;
    }
    header_buf_.Append(buf.Size() - start_offset);
    std::copy(buf.Begin() + start_offset, buf.End(), header_buf_.Begin());
    return reply;
}

void ShadowsocksClient::DoInitializeProtocol(Peer &peer, BasicProtocol::NextStage next) {
    Wrap(header_buf_);
    boost::asio::async_write(
        peer.socket, header_buf_.GetConstBuffer(),
        [next](boost::system::error_code ec, size_t length) {
            if (ec) {
                LOG(INFO) << "unexcepted error while initializing protocol: " << ec;
                return;
            }
            next();
        }
    );
}

void ShadowsocksServer::DoReadHeader(Peer &peer, NextStage next, size_t at_least) {
    boost::asio::async_read(
        peer.socket,
        peer.buf.GetBuffer(),
        boost::asio::transfer_at_least(at_least),
        [this, &peer, next = std::move(next)](boost::system::error_code ec, size_t length) {
            if (ec) {
                LOG(INFO) << "unexcepted error while initializing protocol: " << ec;
                return;
            }

            ssize_t valid_length = UnWrap(peer.buf);
            if (valid_length == 0) {
                DoReadHeader(peer, std::move(next));
                return;
            } else if (valid_length < 0) {
                LOG(WARNING) <<  "protocol_hook error";
                return;
            }

            header_buf_.AppendData(peer.buf);
            peer.buf.Reset();

            size_t need_more = socks5::Request::NeedMore(header_buf_.GetData() - 3,
                                                         header_buf_.Size() + 3);
            if (need_more) {
                LOG(TRACE) << "need more: " << need_more;
                DoReadHeader(peer, std::move(next), need_more);
                return;
            }

            if (ParseHeader(header_buf_, 0) != socks5::SUCCEEDED_REP) {
                LOG(INFO) << "invalid header";
                return;
            }
            header_buf_.DeQueue(header_length_);
            peer.buf.AppendData(header_buf_);
            next();
        }
    );
}

