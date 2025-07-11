/*
Copyright 2022 The Photon Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "streams.h"
#include <unordered_set>
#include "photon/common/alog.h"
#include "photon/common/iovector.h"
#include "photon/thread/thread.h"

namespace photon {
namespace net {
namespace http {

void LE_bswap32(void* p) {
#if IS_LITTLE_ENDIAN
    auto p_ = (uint32_t*)p;
    *p_ = __builtin_bswap32(*p_);
#endif
}
void LE_bswap16(void* p) {
#if IS_LITTLE_ENDIAN
    auto p_ = (uint16_t*)p;
    *p_ = __builtin_bswap16(*p_);
#endif
}
inline void FrameHeader::encode() {
    LE_bswap32(this);
    stream_id &= MASK_31BIT;
    LE_bswap32(&stream_id);
}
inline void FrameHeader::decode() {
    LE_bswap32(this);
    LE_bswap32(&stream_id);
    stream_id &= MASK_31BIT;
}
inline void HeadersFrameHeader::encode() {
    FrameHeader::encode();
    if (padded())
        LE_bswap32(&ext<uint32_t>(1));
}
inline void HeadersFrameHeader::decode() {
    FrameHeader::decode();
    if (padded())
        LE_bswap32(&ext<uint32_t>(1));
}
inline void HeadersFrameHeader::encode() {
    FrameHeader::encode();
    LE_bswap32(&ext(0));
}
inline void HeadersFrameHeader::decode() {
    FrameHeader::decode();
    LE_bswap32(&ext(0));
}
inline void ResetStreamFrameHeader::encode() {
    FrameHeader::encode();
    LE_bswap32(&error_code);
}
inline void ResetStreamFrameHeader::decode() {
    FrameHeader::decode();
    LE_bswap32(&error_code);
}
inline void SettingsFrameHeader::_bswap_all() {
    for (size_t i = 0; i < count(); ++i) {
        auto& p = (*this)[i];
        LE_bswap16(&p.id);
        LE_bswap32(&p.value);
    }
}
inline void SettingsFrameHeader::encode() {
    FrameHeader::encode();
    _bswap_all();
}
inline void SettingsFrameHeader::decode() {
    FrameHeader::decode();
    _bswap_all();
}
inline void PushPromiseFrameHeader::encode() {
    FrameHeader::encode();
    auto& psid = ext<uint32_t>(padded());
    psid &= MASK_31BIT; LE_bswap32(&psid);
}
inline void PushPromiseFrameHeader::decode() {
    FrameHeader::decode();
    auto& psid = ext<uint32_t>(padded());
    LE_bswap32(&psid); psid &= MASK_31BIT;
}
inline void GoawayFrameHeader::encode() {
    FrameHeader::encode();
    last_stream_id &= MASK_31BIT;
    LE_bswap32(&last_stream_id);
    LE_bswap32(&error_code);
}
inline void GoawayFrameHeader::decode() {
    FrameHeader::decode();
    LE_bswap32(&last_stream_id);
    last_stream_id &= MASK_31BIT;
    LE_bswap32(&error_code);
}
inline void WindowUpdateFrameHeader::encode() {
    FrameHeader::encode();
    LE_bswap32(&window_size_increment);
}
inline void WindowUpdateFrameHeader::decode() {
    FrameHeader::decode();
    LE_bswap32(&window_size_increment);
}

const static char http2_preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const static char http2_alpn[] = "h2";

class ConnectionBase : public Connection {
public:
    ISocketStream* _socket;
    mutex _socket_mutex_r, _socket_mutex_w;

    struct Stream {
        uint32_t id, state;
        thread* receiver;
        constexpr static uint32_t MAX_ID = 0x7fffffff;
        enum { idle, open, reserved, half_closed, closed };
        bool operator == (uint32_t id) const { return this->id == id; }
    };
    struct StreamHash {
        size_t operator()(const Stream& s) const { return std::hash<uint32_t>()(s.id); }
        size_t operator()(uint32_t id) const { return std::hash<uint32_t>()(id); }
    };
    uint32_t _min_stream_id = 0, _next_stream_id = 0;
    using set = std::unordered_set<Stream, StreamHash>;
    set _streams;

    // set::iterator find_stream(uint32_t id) {
    //     if (unlikely(id < _min_stream_id || id >= _next_stream_id || _streams.empty()))
    //         return _streams.end();
    //     return _streams.find(id);
    // }

    explicit ConnectionBase(ISocketStream* socket) :
        _socket(socket) {
        // _frame.length = 0;
        // _frame.type = 0;
        // assert(&_frame.ext<char>(0) == _padding);
    }

    template<typename T, size_t N = 20> // 20 bytes is big enough for *all* FrameHeaders
    struct Extension : public T {
        static_assert(std::is_base_of<FrameHeader, T>::value, "T must be FrameHeader");
        static_assert(sizeof(T) <= N, "T must be smaller than N");
        Extension() = default;
        Extension(uint8_t type, uint32_t stream_id) {
            this->type = type;
            this->stream_id = stream_id;
            this->flags = 0;
        }
        char _extension[N - sizeof(T)];
    };

    int write_data(uint32_t stream_id, Buffer body, bool end_stream, uint8_t padding = 0) {
        Extension<DataFrameHeader> h(FrameHeader::DATA, stream_id);
        h.length = h.size() + body.size + padding;
        if (padding)  { h.set_padded(); h.ext(0) = padding; }
        if (end_stream) h.set_end_stream();
        return write_frame(h, body, padding);
    }
    struct HeadersOptions {
        uint8_t padding = 0;
        bool end_stream = false;
        bool priority   = false;
        uint8_t weight  = 0;
        uint32_t stream_dependency : 31;
        uint8_t exclusive : 1;
    }__attribute__((packed));
    int write_headers(uint32_t stream_id, Buffer fields, HeadersOptions opt) {
        Extension<HeadersFrameHeader> h(FrameHeader::HEADERS, stream_id);
        if (opt.end_stream) h.set_end_stream();
        if (opt.padding)  { h.set_padded(); h.ext(0) = opt.padding; }
        if (opt.priority)   h.set_priority(opt.stream_dependency,
                             opt.exclusive, opt.weight);
        h.set_end_headers();  // todo: multi-frame headers
        return write_frame(h, fields);
    }
    int write_priority(uint32_t stream_id, bool exclusive, uint32_t stream_dependency, uint8_t weight) {
        Extension<PriorityFrameHeader> h(FrameHeader::PRIORITY, stream_id);
        h.length = h.size();
        h.exclusive = exclusive;
        h.stream_dependency = stream_dependency;
        h.weight = weight;
        return write_frame(h);
    }
    int write_reset_stream(uint32_t stream_id, uint32_t error_code) {
        Extension<ResetStreamFrameHeader> h(FrameHeader::RST_STREAM, stream_id);
        h.length = h.size();
        h.error_code = error_code;
        return write_frame(h);
    }
    int write_settings(uint32_t stream_id, bool ack,
            const SettingsFrameHeader::Setting* settings, uint16_t count) {
        Extension<SettingsFrameHeader> h(FrameHeader::SETTINGS, stream_id);
        h.length = h.size();
        if (ack) h.set_ack();
        return write_frame(h, {settings, count * sizeof(*settings)});
    }
    int write_push_promise(uint32_t stream_id, uint32_t promised_stream_id, uint8_t padding,
            bool end_headers, Buffer fields) {
        Extension<PushPromiseFrameHeader> h(FrameHeader::PUSH_PROMISE, stream_id);
        if (end_headers) h.set_end_headers();
        if (padding)   { h.set_padded(); h.ext(0) = padding; }
        h.set_promise_stream_id(promised_stream_id);
        h.length = h.size() + fields.size + padding;
        return write_frame(h, fields);
    }
    int write_ping(uint32_t stream_id, bool ack, const void* data) {
        Extension<PingFrameHeader> h(FrameHeader::PING, stream_id);
        if (ack) h.set_ack();
        memcpy(h.data, data, 8);
        h.length = h.size();
        return write_frame(h);
    }
    int write_goaway(uint32_t last_stream_id, uint32_t error_code, Buffer additional_debug_data) {
        Extension<GoawayFrameHeader> h(FrameHeader::GOAWAY, 0);
        h.last_stream_id = last_stream_id;
        h.error_code = error_code;
        h.length = sizeof(h) + additional_debug_data.size;
        return write_frame(h, additional_debug_data);
    }
    int write_window_update(uint32_t stream_id, uint32_t increment) {
        Extension<WindowUpdateFrameHeader> h(FrameHeader::WINDOW_UPDATE, stream_id);
        h.window_size_increment = increment;
        h.length = h.size();
        return write_frame(h);
    }
    int write_continuation(uint32_t stream_id, bool end_headers, Buffer fields) {
        Extension<ContinuationFrameHeader> h(FrameHeader::CONTINUATION, stream_id);
        if (end_headers) h.set_end_headers();
        h.length = h.size();
        return write_frame(h, fields);
    }
    template<typename T, size_t N>
    int write_frame(Extension<T, N>& h, Buffer body = {}, uint8_t padding = 0) {
        h.encode();
        DEFER(h.decode());
        return write_frame(&h, h.length, body, padding);
    }
    int write_frame(const void* buf, size_t len, Buffer body, uint8_t padding = 0) {
        struct iovec iov[3];
        int iovcnt = 1;
        iov[0] = {(void*)buf, len};
        if (body.size) iov[iovcnt++] = body;
        const static char padding_buf[256] = {0};
        if (padding) iov[iovcnt++] = {(void*)padding_buf, padding};
        SCOPED_LOCK(_socket_mutex_w);
        return (int)_socket->writev(iov, iovcnt);
    }

    using GenericFrame = Extension<FrameHeader>;

    GenericFrame _frame;
    uint8_t _header_length = 0, _remaining_length = 0;
    int _do_read_frame_header(Timeout timeout) {
        if (_remaining_length) {
            assert(_header_length < sizeof(_frame));
            memmove(&_frame, (char*)&_frame + _header_length, _remaining_length);
        }
        // _socket->timeout(timeout);
        auto ret = _socket->recv_at_least((char*)&_frame + _remaining_length,
                                          sizeof(_frame) - _remaining_length,
                                     sizeof(FrameHeader) - _remaining_length);
        if (ret < 0) { failure: LOG_ERRNO_RETURN(0, ret, "faild to read socket"); }
        if (ret < sizeof(FrameHeader)) { closed: LOG_ERROR_RETURN(EBADF, -1, "socket closed"); }
        if (_frame.type > FrameHeader::CONTINUATION) { type: LOG_ERROR_RETURN(EINVAL, -1, "invalid frame type:", _frame.type); }

        _header_length = 0;
        ret += _remaining_length;
        switch(_frame.type) {
            #define CASE(HEADER, Header) case FrameHeader::HEADER: \
                _header_length = ((Header ## FrameHeader*)&_frame)->size(); break;
            CASE(DATA, Data);
            CASE(HEADERS, Headers);
            CASE(PRIORITY, Priority);
            CASE(RST_STREAM, ResetStream);
            CASE(SETTINGS, Settings);
            CASE(PUSH_PROMISE, PushPromise);
            CASE(PING, Ping);
            CASE(GOAWAY, Goaway);
            CASE(WINDOW_UPDATE, WindowUpdate);
            CASE(CONTINUATION, Continuation);
            default: goto type;
            #undef CASE
        }
        if (likely(ret >= _header_length)) {
            _remaining_length = ret - _header_length;
        } else {
            _remaining_length = 0;
            ssize_t more = _header_length - ret;
            ret = _socket->read((char*)&_frame + ret, more);
            if (ret < 0) goto failure;
            if (ret < more) goto closed;
        }
        return 0;
    }

    bool process_generic_frame() {

    }

    void stream_error(){

    }

    photon::spinlock _readers_lock;
    std::unordered_map<uint32_t, std::pair<thread*, GenericFrame*>> _readers;
    GenericFrame read_frame_header(uint32_t stream_id, Timeout timeout) {
        GenericFrame result;
        int ret = _socket_mutex_r.try_lock();
        if (ret < 0) {
            auto ok = ({ SCOPED_LOCK(_readers_lock);
                _readers.insert({stream_id, {CURRENT, &result}}).second; });
            if (!ok)
                LOG_ERROR_RETURN(EINVAL, result, "failed to insert reader to map");
            ret = thread_usleep(timeout);
            if (ret == 0) // timeout
            // result has been filled by other threads
            if (!result.length) goto do_read;   // continue reading
            assert(result.stream_id == stream_id);
            { SCOPED_LOCK(_readers_lock);   // the it returned by insert() may
            _readers.erase(stream_id); }    // have already become invalid
        }

    do_read:
        DEFER(_socket_mutex_r.unlock());
        while(!timeout.expired()) {
            ret = _do_read_frame_header(timeout);
            if (process_generic_frame()) { }
            else if (_frame.stream_id == stream_id) {
                result = _frame;
                auto th = [&]() -> thread* {
                    SCOPED_LOCK(_readers_lock);
                    if (_readers.empty()) return nullptr;
                    auto& p = _readers.begin()->second;
                    p.second->length = 0; // resume a reader to continue reading
                    return p.first;
                }();
                if (th) thread_interrupt(th, -1);
                return result;
            } else {
                auto th = [&]() -> thread* {
                    SCOPED_LOCK(_readers_lock);
                    auto it = _readers.find(_frame.stream_id);
                    if (it == _readers.end()) return nullptr;
                    auto& p = it->second;
                    *p.second = _frame;
                    assert(_frame.length > 0);
                    return p.first;
                }();
                if (th) thread_interrupt(th, -1);
                else stream_error();
            }
        }
        return result;
    }
};

class ClientConnection : public ConnectionBase {
public:
    using ConnectionBase::ConnectionBase;

    void connection_control() {

    }
    int _do_read_frame_header() {
    again:
        assert(!_frame.length);
        ssize_t ret = _socket->read(&_frame, sizeof(_frame));
        if (ret != sizeof(_frame))
            LOG_ERRNO_RETURN(0, -1, "failed to read frame header");
        if (_frame.stream_id == 0) {
            connection_control();
            goto again;
        }
        return 0;
    }
    void resume_a_reader() {
        auto it = _readers.find(_frame.stream_id);
        if (it != _readers.end()) {
            thread_interrupt(it->second);
            _readers.erase(it);
        }
    }
    std::unordered_map<uint32_t, thread*> _readers;
    ssize_t read(uint32_t stream_id, uint8_t type, void* buf, size_t len) {
        SCOPED_LOCK(_socket_mutex);
        if (!_frame.length) {
            _do_read_frame_header();
        }
        if (_frame.length) {
            if (_frame.stream_id == stream_id) {
                goto do_readv;
            } else {
                resume_a_reader();
            }
        }

        do {
            auto ok = _readers.insert({stream_id, CURRENT}).second;
            if (!ok) LOG_ERROR_RETURN(EINVAL, -1, "stream (`) can not be read concurrently", stream_id);
            int r = thread_usleep_unlocked(-1, _socket_mutex);
            assert(r < 0 && errno == EINTR); // resumed by a peer thread
            assert(_readers.count(stream_id) == 0); // evicted when wake up
            assert(_frame.length && _frame.stream_id == stream_id);
        } while(0);

    do_readv:
        assert(_frame.length);
        iovector_view v(iov, iovcnt);
        v.shrink_to(_frame.length);
        auto r = _socket->readv_mutable(v.iov, v.iovcnt);
        if (r < 0)
            LOG_ERROR_RETURN(0, r, "failed to read from socket");
        assert((size_t)r <= _frame.length);
        _frame.length -= r;
        if (!_frame.length &&
            _do_read_frame_header() == 0)
                resume_a_reader();
        return r;
    }

    class Stream : public ISocketStream {
    public:
        Connection* _con;
        Stream(Connection* c) : _con(c) { }
    };

    ISocketStream* new_stream() {
        auto s = new Stream(this);
        return s;
    }
};


Object* new_connection(ISocketStream* socket, bool is_client) {
    return new Connection(socket, is_client);
}

ISocketStream* new_stream(Object* c) {
    return static_cast<Connection*>(c)->new_stream();
}


}
}
}
