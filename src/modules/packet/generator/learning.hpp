#ifndef _OP_PACKET_GENERATOR_LEARNING_HPP_
#define _OP_PACKET_GENERATOR_LEARNING_HPP_

#include <vector>
#include <map>
#include <variant>

#include "lwip/netif.h"

#include "lib/packet/type/ipv4_address.hpp"
#include "lib/packet/type/mac_address.hpp"

namespace openperf::packet::generator {

using unresolved = std::monostate;
using mac_type = std::variant<unresolved, libpacket::type::mac_address>;

// XXX: this should be an unordered_map, but it doesn't like
// ipv4_address class as the key type.
using learning_result_map = std::map<libpacket::type::ipv4_address, mac_type>;

// Concrete types representing individual states.
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

/**
 * @brief Finite State Machine class that handles MAC learning.
 *
 */
class learning_state_machine
{
public:
    /**
     * @brief Start MAC learning process.
     *
     * @param interface lwip interface to use for learning
     * @param to_learn list of IP addresses to learn
     * @return true if learning started successfully
     * @return false learning did not start
     */
    bool
    start_learning(netif* interface,
                   const std::vector<libpacket::type::ipv4_address>& to_learn);

    /**
     * @brief Retry failed MAC learning items.
     *
     * @return true if learning started successfully
     * @return false learning did not start
     */
    bool retry_failed();

    /**
     * @brief Update resolved addresses from lwip stack MAC learning cache.
     *
     */
    void check_learning();

    /**
     * @brief Drive state machine to completion state (state_done if all entries
     * resolved, state_timeout otherwise.)
     *
     */
    void stop_learning();

    const learning_result_map& get_results() { return results; }

    /**
     * @brief Did learning resolve all requested MAC addresses?
     *
     * Will return false if called before learning started.
     *
     * @return true all requested MAC addresses resolved
     * @return false at least one requested MAC address did not resolve.
     */
    bool resolved()
    {
        return (std::holds_alternative<state_done>(current_state));
    }

    /**
     * @brief Shorthand for state machine starting up or in process of learning.
     *
     * @return true state machine learning in progress.
     * @return false state machine learning stopped.
     */
    bool in_progress()
    {
        return (std::holds_alternative<state_start>(current_state)
                || std::holds_alternative<state_learning>(current_state));
    }

private:
    /**
     * @brief Internal impl method used by start/retry methods since
     * implementation is mostly the same.
     *
     * @return true learning started
     * @return false learning did nto start
     */
    bool start_learning_impl();

    netif* intf = nullptr;
    learning_result_map results;
    learning_state current_state;
};

} // namespace openperf::packet::generator

#endif /* _OP_PACKET_GENERATOR_LEARNING_HPP_ */