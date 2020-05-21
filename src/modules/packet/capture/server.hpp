#ifndef _OP_PACKET_CAPTURE_SERVER_HPP_
#define _OP_PACKET_CAPTURE_SERVER_HPP_

#include <map>
#include <vector>

#include "core/op_core.h"
#include "packet/capture/api.hpp"
#include "packet/capture/sink.hpp"
#include "packetio/internal_client.hpp"

namespace openperf::packet::capture::api {

class server
{
    core::event_loop& m_loop;
    packetio::internal::api::client m_client;
    std::unique_ptr<void, op_socket_deleter> m_socket;

    /*
     * Since sinks know their own id's, we store them in a
     * vector.  That way we don't needlessly store each id
     * twice.
     */
    using sink_value_type = packetio::packet::generic_sink;
    std::vector<sink_value_type> m_sinks;

    /*
     * Capture results don't know their own id's, so we store
     * those in an associative container with the id as the key.
     * Furthermore, we (the server) own the results.  The sink
     * just borrows a result instance when running.
     */
    using result_value_type = sink_result;
    using result_value_ptr = std::unique_ptr<result_value_type>;
    using result_map = std::map<core::uuid, result_value_ptr>;

    /* result id --> result */
    result_map m_results;

    /*
     * Capture sink and results objects can not be deleted when
     * a pcap transfer is in progress or cleaning up.
     * In order to allow the REST API to delete objects in this
     * state, the objects which can not be deleted are put into
     * trash buckets grouped by sink ID.  When transfers complete,
     * the garbage_collect() function is called to delete all objects
     * which have completed transfers.
     */
    struct trash_bucket
    {
        std::optional<sink_value_type> sink;
        std::vector<result_value_ptr> results;
    };
    using trash_map = std::map<std::string, std::unique_ptr<trash_bucket>>;

    trash_map m_trash;

public:
    server(void* context, core::event_loop& loop);

    reply_msg handle_request(const request_list_captures&);
    reply_msg handle_request(const request_create_capture&);
    reply_msg handle_request(const request_delete_captures&);

    reply_msg handle_request(const request_get_capture&);
    reply_msg handle_request(const request_delete_capture&);

    reply_msg handle_request(const request_start_capture&);
    reply_msg handle_request(const request_stop_capture&);

    reply_msg handle_request(const request_list_capture_results&);
    reply_msg handle_request(const request_delete_capture_results&);
    reply_msg handle_request(const request_get_capture_result&);
    reply_msg handle_request(const request_delete_capture_result&);

    reply_msg handle_request(request_create_capture_transfer&);
    reply_msg handle_request(const request_delete_capture_transfer&);

    int handle_capture_stop_timer(uint32_t timeout_id);

    int garbage_collect();

private:
    bool has_active_transfer(const sink& sink) const;

    void add_trash(sink_value_type& sink);
    void add_trash(result_value_ptr&& result);
};

} // namespace openperf::packet::capture::api

#endif /* _OP_PACKET_CAPTURE_SERVER_HPP_ */