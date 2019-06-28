#ifndef _ICP_PACKETIO_INTERNAL_API_H_
#define _ICP_PACKETIO_INTERNAL_API_H_

#include <optional>
#include <string>

#include <zmq.h>
#include "tl/expected.hpp"

#include "packetio/generic_event_loop.h"
#include "packetio/generic_workers.h"

namespace icp::packetio::internal::api {

constexpr size_t name_length_max = 64;

extern std::string_view endpoint;

struct task_data {
    char name[name_length_max];
    workers::context ctx;
    event_loop::event_notifier notifier;
    event_loop::callback_function callback;
    std::any arg;
};

struct request_task_add {
    task_data task;
};

struct request_task_del {
    std::string task_id;
};

struct reply_task_add {
    std::string task_id;
};

struct reply_ok {};

struct reply_error {
    int value;
};

using request_msg = std::variant<request_task_add,
                                 request_task_del>;

using reply_msg = std::variant<reply_task_add,
                               reply_ok,
                               reply_error>;


struct serialized_msg {
    zmq_msg_t type;
    zmq_msg_t data;
};

serialized_msg serialize_request(const request_msg& request);
serialized_msg serialize_reply(const reply_msg& reply);

tl::expected<request_msg, int> deserialize_request(const serialized_msg& msg);
tl::expected<reply_msg, int> deserialize_reply(const serialized_msg& msg);

int send_message(void* socket, serialized_msg&& msg);
tl::expected<serialized_msg, int> recv_message(void* socket, int flags = 0);

}

#endif /* _ICP_PACKETIO_INTERNAL_API_H_ */
