/**
 * swagger <-> libpacket transmogrify implementation for Ethernet
 *
 * This file is automatically generated by the transmogrify code generator.
 * Do not edit this file manually.
 **/

#include "ethernet.hpp"

namespace openperf::packet::protocol::transmogrify {

std::shared_ptr<swagger::v1::model::PacketProtocolEthernet> to_swagger(libpacket::protocol::ethernet& src)
{
    auto dst = std::make_shared<swagger::v1::model::PacketProtocolEthernet>();

    dst->setDestination(to_string(get_ethernet_destination(src)));
    dst->setSource(to_string(get_ethernet_source(src)));
    dst->setEtherType(get_ethernet_ether_type(src));

    return (dst);
}

libpacket::protocol::ethernet to_protocol(const std::shared_ptr<swagger::v1::model::PacketProtocolEthernet>& src)
{
    auto dst = libpacket::protocol::ethernet{};

    if (src) {
        if (src->destinationIsSet())
        {
            set_ethernet_destination(dst, libpacket::type::mac_address(src->getDestination()));
        }
        if (src->sourceIsSet())
        {
            set_ethernet_source(dst, libpacket::type::mac_address(src->getSource()));
        }
        if (src->etherTypeIsSet())
        {
            set_ethernet_ether_type(dst, src->getEtherType());
        }
    }

    return (dst);
}

}
