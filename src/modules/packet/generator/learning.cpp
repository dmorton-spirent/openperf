#include "packet/generator/learning.hpp"

#include "packet/stack/lwip/tcpip.hpp"
#include "lwip/priv/tcpip_priv.h"
#include "lwip/sys.h"
#include "lwip/memp.h"
#include "lwip/mem.h"
#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/pbuf.h"
#include "lwip/etharp.h"
#include "netif/ethernet.h"
#include "arpa/inet.h"

// FIXME: prolly not needed for production
#include <iostream>

namespace openperf::packet::generator {

static void really_start_learning(void* arg)
{
    auto lp = reinterpret_cast<learning_params*>(arg);

    // learning_params.ipv4_addresses contains a unique list of IPv4 addresses
    // to learn.
    // Addresses are assumed to be on-link. Caller must apply routing logic, and
    // must not send IP addresses from a different subnet.

    std::for_each(
        lp->ipv4_addresses.begin(), lp->ipv4_addresses.end(), [&](auto& addr) {

            //FIXME: eventually we'll get the result map here. read-only of course.
            // Iterate through it and try to learn all IPs that have a corresponding MAC in unresolved state.
            // This will let us do retry the same way we do regular learning.
            // Especially since the stack automatically retries things for us. So our retry is just gravy.
            // OR could make manual control over learning only retry failed items...

            ip4_addr_t target;
            // FIXME: need to memcpy stuff here. addr.data() returns a pointer
            // to the first octet of the ip addr.
            memcpy(&target.addr, addr.data(), addr.width);
            // target.addr = *addr.data();
            // addr.width;

            printf("going to learn MAC for IP: %x\n", target.addr);

            auto result = etharp_query(lp->intf, &target, nullptr);
            if (result != ERR_OK) {
                std::cout << "got error back from etharp_query!" << std::endl;
            }
        });

    // err_t etharp_query(struct netif *netif, const ip4_addr_t *ipaddr, struct
    // pbuf *q);
    // ip4_addr_t target;
    // target.addr = htonl(0xc6336414);

    // auto result = etharp_query(lp->intf, &target, nullptr);
    // if (result != ERR_OK) {
    //     std::cout << "got error back from etharp_query!" << std::endl;
    // }
}

// Return true if learning started, false otherwise.
bool learning_state_machine::start_learning(learning_params& lp)
{
    // If we're already learning, don't start again.
    if (in_progress()) { return (false); }

    current_state = state_start{};

    params = std::move(lp);
    results.results.clear();

    // Populate results with IP addresses.
    std::transform(
        params.ipv4_addresses.begin(),
        params.ipv4_addresses.end(),
        std::inserter(results.results, results.results.end()),
        [](auto& ip_addr) {
            return (std::make_pair(ip_addr, learning_results::unresolved{}));
        });

    if (auto res = tcpip_callback(really_start_learning, &this->params);
        res != ERR_OK) {
        current_state = state_timeout{};
        return (false);
    }

    // FIXME: add callback here to start periodically polling learning results.
    // For now have the caller simulate the behavior.

    current_state = state_learning{};

    return (true);
}

static void check_arp_cache(void* arg)
{
    auto results = reinterpret_cast<learning_results*>(arg);

    // FIXME: for debugging only.
    std::for_each(
        results->results.begin(), results->results.end(), [](auto& item_pair) {
            std::cout << "checking if this address resolved: "
                      << item_pair.first << std::endl;
        });

    // err_t etharp_query(struct netif *netif, const ip4_addr_t *ipaddr, struct
    // pbuf *q);
    // ip4_addr_t target;
    // target.addr = htonl(0xc6336414);

    // ip4_addr_t entryAddr;
    // eth_addr entryMac;
    // netif entryIntf;

    ip4_addr_t* entryAddrPtr = nullptr;
    eth_addr* entryMacPtr = nullptr;
    netif* entryIntfPtr = nullptr;

    for (size_t i = 0; i < ARP_TABLE_SIZE; i++) {
        // LwIP refers to resolved MACs as "stable entries" in the ARP cache.
        auto stable_entry =
            etharp_get_entry(i, &entryAddrPtr, &entryIntfPtr, &entryMacPtr);

        if (!stable_entry) { continue; }

        // be careful here. network byte order problems can happen.
        auto found_result = results->results.find(
            libpacket::type::ipv4_address(ntohl(entryAddrPtr->addr)));
        if (found_result == results->results.end()) {
            // Guess we weren't looking for this address.
            // Remember, the stack is shared by all generators.
            continue;
        }

        std::cout
            << "found a match for this IP while really checking learning: "
            << found_result->first << std::endl;

        if (std::holds_alternative<libpacket::type::mac_address>(
                found_result->second)) {
            // We already know this address.
            continue;
        }

        std::cout << "gonna store resolved MAC for this IP: "
                  << found_result->first << std::endl;

        printf("Resolved MAC: %x %x %x %x %x %x\n",
               entryMacPtr->addr[0],
               entryMacPtr->addr[1],
               entryMacPtr->addr[2],
               entryMacPtr->addr[3],
               entryMacPtr->addr[4],
               entryMacPtr->addr[5]);

        found_result->second.emplace<libpacket::type::mac_address>(
            (const uint8_t*)entryMacPtr->addr);
    }

    // bool resolved = false;
    // for (size_t i = 0; i < ARP_TABLE_SIZE; i++) {
    //     // int etharp_get_entry(size_t i, ip4_addr_t **ipaddr, struct netif
    //     // **netif, struct eth_addr **eth_ret);
    //     auto found =
    //         etharp_get_entry(i, &entryAddrPtr, &entryIntfPtr, &entryMacPtr);

    //     if (found) {
    //         printf("offset: %lu, target.addr: %x, entryAddr: %x\n",
    //                i,
    //                target.addr,
    //                entryAddrPtr->addr);
    //         if (target.addr == entryAddrPtr->addr) {
    //             resolved = true;
    //             break;
    //         }
    //     }
    // }

    // std::cout << "IP address resolved? " << std::boolalpha << resolved
    //           << std::endl;

    // if (entryAddrPtr)
    //     std::cout << "IP: " << std::hex << ntohl(entryAddrPtr->addr);
    // if (entryMacPtr)
    //     // std::cout << " MAC: " << std::hex << entryMacPtr->addr[5];
    //     printf(" MAC: %x", entryMacPtr->addr[5]);
    // if (entryIntfPtr)
    //     std::cout << " interface: " << std::hex << entryIntfPtr->num
    //               << std::endl;

    // auto result = etharp_query(lp->intf, &target, nullptr);
    // if (result != ERR_OK) {
    //     std::cout << "got error back from etharp_query!" << std::endl;
}

bool all_addresses_resolved(const learning_results& results)
{
    auto first_unresolved = std::find_if(
        results.results.begin(), results.results.end(), [](auto& address_pair) {
            return std::holds_alternative<learning_results::unresolved>(
                address_pair.second);
        });

    return (first_unresolved == results.results.end());
}

void learning_state_machine::check_learning()
{
    // FIXME: need this?
    // if (results.results.empty()) { return; }

    // FIXME: make sure this is only called once at a time. Running multiple
    // copies at the same time could cause serious problems with updating the
    // data structure.

    tcpip_callback(check_arp_cache, &this->results);
    //FIXME: check_arp_cache doesn't do much. safest to block while the check is being done.
    usleep(500000); // simulate blocking while callback does its thing. 0.5 seconds.

    if (all_addresses_resolved(results)) {
        current_state = state_done{};
    }
}

} // namespace openperf::packet::generator