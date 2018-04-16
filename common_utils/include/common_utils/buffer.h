#ifndef __BUFFER_H__
#define __BUFFER_H__

#include <cstdint>
#include <vector>
#include <algorithm>
#include <boost/asio.hpp>

#include "common_utils/common.h"

class Buffer;

namespace std {

constexpr uint8_t *begin(Buffer &buf) noexcept;
constexpr const uint8_t *begin(const Buffer &buf) noexcept;

constexpr uint8_t *end(Buffer &buf) noexcept;
constexpr const uint8_t *end(const Buffer &buf) noexcept;

}; // namespace std

class Buffer {
public:
    Buffer(size_t max_length = 8192, size_t max_read_length_once = 16384)
        : buf_(std::max((size_t)1024, max_length)),
          curr_(0), max_read_length_once_(max_read_length_once) {
    }

    void DeQueue(size_t len) {
        size_t total = curr_;
        if (len > total) {
            LOG(FATAL) << "Buffer::Dequeue len > total";
            len = total;
        }
        std::copy(Begin() + len, End(), Begin());
        curr_ = total - len;
    }

    void Append(size_t len) {
        PrepareCapacity(len);
        curr_ += len;
    }

    template<class Container>
    void AppendData(const Container &cont) {
        PrepareCapacity(cont.size());
        std::copy(std::begin(cont), std::end(cont), End());
        Append(cont.size());
    }

    void AppendData(const uint8_t *buf, size_t len) {
        PrepareCapacity(len);
        std::copy_n(buf, len, End());
        Append(len);
    }

    template<class Container>
    void PrependData(const Container &cont) {
        size_t extra_len = cont.size();
        PrepareCapacity(extra_len);
        std::copy_backward(Begin(), End(), End() + extra_len);
        Append(extra_len);
        std::copy(std::begin(cont), std::end(cont), Begin());
    }

    void PrependData(const uint8_t *buf, size_t len) {
        PrepareCapacity(len);
        std::copy_backward(Begin(), End(), End() + len);
        Append(len);
        std::copy_n(buf, len, Begin());
    }

    void Reset(size_t new_len = 0) {
        ReserveCapacity(new_len);
        curr_ = new_len;
    }

    void PrepareCapacity(size_t more_length) {
        size_t total = Size() + more_length;
        if (total > Capacity()) {
            ReserveCapacity(total);
        }
    }

    void ReserveCapacity(size_t new_capacity) {
        if (Capacity() < new_capacity) {
            buf_.resize(new_capacity);
        }
    }

    boost::asio::mutable_buffer GetBuffer() {
        size_t rest_length = Capacity() - Size();
        size_t avail_length = std::min(max_read_length_once_, rest_length);
        return boost::asio::buffer(End(), avail_length);
    }

    boost::asio::const_buffer GetConstBuffer() const {
        return boost::asio::buffer(Begin(), Size());
    }

    size_t Capacity() const { return buf_.size(); }

    uint8_t *Begin() { return buf_.data(); }
    const uint8_t *Begin() const { return buf_.data(); }

    uint8_t *End() { return Begin() + Size(); }
    const uint8_t *End() const { return Begin() + Size(); }

    uint8_t *GetData() { return Begin(); }
    const uint8_t *GetData() const { return Begin(); }

    size_t Size() const { return curr_; }
    size_t size() const { return curr_; }
private:
    std::vector<uint8_t> buf_;
    size_t curr_;
    size_t max_read_length_once_;
};

namespace std {

constexpr uint8_t *begin(Buffer &buf) noexcept {
    return buf.Begin();
}

constexpr const uint8_t *begin(const Buffer &buf) noexcept {
    return buf.Begin();
}

constexpr uint8_t *end(Buffer &buf) noexcept {
    return buf.End();
}

constexpr const uint8_t *end(const Buffer &buf) noexcept {
    return buf.End();
}

}; // namespace std

#endif

