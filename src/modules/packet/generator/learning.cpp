#include "packet/generator/learning.hpp"

#include "lwip/priv/tcpip_priv.h"
#include "lwip/etharp.h"
#include "arpa/inet.h"

#include <future>

namespace openperf::packet::generator {

static constexpr std::chrono::seconds learning_start_timeout(1);
static constexpr std::chrono::seconds learning_check_timeout(1);

bool all_addresses_resolved(const learning_result_map& results);

// Structure that gets "passed" to the stack thread via tcpip_callback.
struct start_learning_params
{
    netif* intf = nullptr;               // lwip interface to use.
    const learning_result_map& to_learn; // addresses to learn.
    std::promise<err_t> barrier; // keep generator and stack threads in sync.
};

static void send_learning_requests(void* arg)
{
    auto slp = reinterpret_cast<start_learning_params*>(arg);

    // start_learning_params contains a unique list of IP addresses to learn.
    // Addresses are assumed to be on-link. Caller must first apply routing
    // logic. Caller must not send IP addresses from a different subnet.

    err_t overall_result = ERR_OK;
    std::for_each(
        slp->to_learn.begin(), slp->to_learn.end(), [&](const auto& addr_pair) {
            // If we've already had an error don't bother trying to learn this
            // address.
            if (overall_result != ERR_OK) { return; }

            // Is this entry unresolved?
            // Don't repeat learning for addresses we've already resolved.
            if (!std::holds_alternative<unresolved>(addr_pair.second)) {
                return;
            }

            ip4_addr_t target;

            memcpy(&target.addr, addr_pair.first.data(), addr_pair.first.width);

            OP_LOG(OP_LOG_TRACE,
                   "Sending ARP request for IP: %s\n",
                   to_string(addr_pair.first).c_str());

            auto result = etharp_query(slp->intf, &target, nullptr);
            if (result != ERR_OK) {
                OP_LOG(OP_LOG_ERROR,
                       "Error (%s) encountered while requesting ARP for "
                       "address: %s",
                       lwip_strerr(result),
                       to_string(addr_pair.first).c_str());
                overall_result = result;
            }
        });

    // Return ERR_OK if nothing went wrong, else first error we encountered.
    // Since we stop trying after the first error technically that would be the
    // only error.
    slp->barrier.set_value(overall_result);
}

// Return true if learning started, false otherwise.
bool learning_state_machine::start_learning(
    netif* interface,
    const std::vector<libpacket::type::ipv4_address>& to_learn)
{
    // If we're already learning, don't start again.
    if (in_progress()) { return (false); }

    // Are we being asked to learn nothing?
    if (to_learn.empty()) { return (false); }

    m_intf = interface;
    m_results.clear();

    // Populate results with IP addresses.
    std::transform(
        to_learn.begin(),
        to_learn.end(),
        std::inserter(m_results, m_results.end()),
        [](auto& ip_addr) { return (std::make_pair(ip_addr, unresolved{})); });

    return (start_learning_impl());
}

bool learning_state_machine::retry_failed()
{
    // Are we being asked to retry when no items failed?
    if (all_addresses_resolved(m_results)) { return (false); }

    return (start_learning_impl());
}

bool learning_state_machine::start_learning_impl()
{
    // If we're already learning, don't start again.
    if (in_progress()) { return (false); }

    // Are we being asked to learn nothing?
    if (m_results.empty()) { return (false); }

    // Do we have a valid interface to learn on?
    if (m_intf == nullptr) { return (false); }

    m_current_state = state_start{};

    start_learning_params slp = {.intf = this->m_intf, .to_learn = this->m_results};
    auto barrier = slp.barrier.get_future();

    // tcpip_callback executes the given function in the stack thread passing it
    // the second argument as void*.
    // send_learning_requests is smart enough to only send requests for results
    // in the unresolved state.
    if (auto res = tcpip_callback(send_learning_requests, &slp);
        res != ERR_OK) {
        m_current_state = state_timeout{};
        return (true);
    }

    // Wait for the all the learning requests to send.
    // We could just return. But it's useful to know if the process succeeded.
    // Plus, the process is non-blocking on the stack side so this won't take
    // long.
    if (barrier.wait_for(learning_start_timeout) != std::future_status::ready) {
        OP_LOG(OP_LOG_ERROR, "Timed out while starting learning.");
        m_current_state = state_timeout{};
        return (false);
    }

    auto learning_status = barrier.get();
    if (learning_status != ERR_OK) { m_current_state = state_timeout{}; }

    m_current_state = state_learning{};

    return (true);
}

// Structure that gets "passed" to the stack thread via tcpip_callback.
struct check_learning_params
{
    learning_result_map& results;
    std::promise<void> barrier;
};

static void check_arp_cache(void* arg)
{
    auto clp = reinterpret_cast<check_learning_params*>(arg);

    ip4_addr_t* entryAddrPtr = nullptr;
    eth_addr* entryMacPtr = nullptr;
    netif* entryIntfPtr = nullptr;

    for (size_t i = 0; i < ARP_TABLE_SIZE; i++) {
        // LwIP refers to resolved MACs as "stable entries" in the ARP cache.
        auto stable_entry =
            etharp_get_entry(i, &entryAddrPtr, &entryIntfPtr, &entryMacPtr);

        if (!stable_entry) { continue; }

        auto found_result = clp->results.find(
            libpacket::type::ipv4_address(ntohl(entryAddrPtr->addr)));
        if (found_result == clp->results.end()) {
            // Guess we weren't looking for this address.
            // Remember, the stack is shared by all generators.
            continue;
        }

        if (std::holds_alternative<libpacket::type::mac_address>(
                found_result->second)) {
            // We already know this address.
            continue;
        }

        found_result->second.emplace<libpacket::type::mac_address>(
            (const uint8_t*)entryMacPtr->addr);
    }

    clp->barrier.set_value();
}

bool all_addresses_resolved(const learning_result_map& results)
{
    return (std::none_of(
        results.begin(), results.end(), [](const auto& address_pair) {
            return std::holds_alternative<unresolved>(address_pair.second);
        }));
}

void learning_state_machine::check_learning()
{
    // Are there results to check?
    if (m_results.empty()) { return; }

    // Are we in the process of learning?
    if (!std::holds_alternative<state_learning>(m_current_state)) { return; }

    check_learning_params clp = {.results = this->m_results};
    auto barrier = clp.barrier.get_future();

    // tcpip_callback executes the given function in the stack thread passing it
    // the second argument as void*.
    if (auto res = tcpip_callback(check_arp_cache, &clp); res != ERR_OK) {
        m_current_state = state_timeout{};
        return;
    }

    // Wait for the all the learning requests to send.
    // We could just return. But it's useful to know if the process succeeded.
    // Plus, the process is non-blocking on the stack side so this won't take
    // long.
    if (barrier.wait_for(learning_check_timeout) != std::future_status::ready) {
        OP_LOG(OP_LOG_ERROR, "Timed out while checking learning status.");
        m_current_state = state_timeout{};
        return;
    }

    // auto check_result = barrier.get();
    // if (check_result != ERR_OK) { current_state = state_timeout{}; }

    if (all_addresses_resolved(m_results)) { m_current_state = state_done{}; }
}

void learning_state_machine::stop_learning()
{
    if (all_addresses_resolved(m_results)) {
        m_current_state = state_done{};
        return;
    }

    m_current_state = state_timeout{};
}

} // namespace openperf::packet::generator