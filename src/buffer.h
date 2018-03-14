#ifndef __BUFFER_H__
#define __BUFFER_H__

#include <cstdint>
#include <vector>
#include <boost/asio.hpp>
#include <boost/log/trivial.hpp>

#include "common.h"

class Buffer {
public:
    Buffer(size_t max_length)
        : buf_(max_length), curr_(0) {
    }

    void DeQueue(size_t len) {
        size_t total = curr_;
        if (len > total) {
            LOG(FATAL) << "Buffer::Dequeue len > total";
            len = total;
        }
        std::copy(buf_.begin() + len, buf_.begin() + total, buf_.begin());
        curr_ = total - len;
    }

    void Append(size_t len) {
        curr_ += len;
    }

    void Reset(size_t new_len = 0) {
        curr_ = new_len;
    }

    size_t Size() const {
        return curr_;
    }

    boost::asio::mutable_buffer get_buffer() {
        return boost::asio::buffer(buf_) + curr_;
    }

    boost::asio::const_buffer get_const_buffer() const {
        return boost::asio::buffer(buf_.data(), curr_);
    }

    uint8_t *get_data() {
        return buf_.data();
    }

private:
    std::vector<uint8_t> buf_;
    size_t curr_;
};

#endif

