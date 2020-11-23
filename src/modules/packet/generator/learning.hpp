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
    struct unresolved {};
    using mac_type = std::variant<unresolved, libpacket::type::mac_address>;

    // FIXME: this should be an unordered_map, but that class doesn't like
    // ipv4_address class as the key type.
    using result_map =
        std::map<libpacket::type::ipv4_address, mac_type>;
    result_map results;
};

class learning_state_machine
{
public:
    void start_learning(learning_params& lp);
    void check_learning();
    const learning_params& get_params() { return params; }

    const learning_results& get_results() { return results; }

private:
    learning_params params;
    learning_results results;
};

} // namespace openperf::packet::generator

#endif /* _OP_PACKET_GENERATOR_LEARNING_HPP_ */