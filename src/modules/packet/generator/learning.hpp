#ifndef _OP_PACKET_GENERATOR_LEARNING_HPP_
#define _OP_PACKET_GENERATOR_LEARNING_HPP_

#include <vector>
#include <map>
#include <variant>

#include "lwip/netif.h"

#include "lib/packet/type/ipv4_address.hpp"
#include "lib/packet/type/mac_address.hpp"

namespace openperf::packet::generator {
struct to_learn
{
    std::vector<libpacket::type::ipv4_address> ipv4_addresses;
};

struct learning_params
{
    netif* intf = nullptr;
    std::vector<libpacket::type::ipv4_address> ipv4_addresses;
};

struct learning_results
{
    using unresolved = std::monostate;
    using mac_type = std::variant<unresolved, libpacket::type::mac_address>;

    // FIXME: this should be an unordered_map, but that class doesn't like
    // ipv4_address class as the key type.
    using result_map = std::map<libpacket::type::ipv4_address, mac_type>;
    result_map results;
};

struct state_start
{};
struct state_learning
{};
struct state_done
{};
struct state_timeout
{};

using learning_state = std::variant<std::monostate,
                                    state_start,
                                    state_learning,
                                    state_done,
                                    state_timeout>;

class learning_state_machine
{
public:
    bool start_learning(learning_params& lp);
    void check_learning();
    const learning_params& get_params() { return params; }

    const learning_results& get_results() { return results; }

    bool resolved()
    {
        return (std::holds_alternative<state_done>(current_state));
    }

    bool in_progress()
    {
        return (std::holds_alternative<state_start>(current_state) || std::holds_alternative<state_learning>(current_state));
    }

private:
    learning_params params; // FIXME: reduce this down to just the interface. no need to save the whole struct.
    learning_results results; // FIXME: pass this to the learning process too.
    learning_state current_state;
};

} // namespace openperf::packet::generator

#endif /* _OP_PACKET_GENERATOR_LEARNING_HPP_ */