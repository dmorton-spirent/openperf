#include "packet/generator/traffic/protocol/ip.hpp"

namespace openperf::packet::generator::traffic::protocol {

void update_context(libpacket::protocol::ipv4& ip,
                    const libpacket::protocol::tcp&) noexcept
{
    set_ipv4_protocol(ip, traffic::protocol::ip::tcp);
}

void update_context(libpacket::protocol::ipv4& ip,
                    const libpacket::protocol::udp&) noexcept
{
    set_ipv4_protocol(ip, traffic::protocol::ip::udp);
}

void update_context(libpacket::protocol::ipv6& ip,
                    const libpacket::protocol::tcp&) noexcept
{
    set_ipv6_next_header(ip, traffic::protocol::ip::tcp);
}

void update_context(libpacket::protocol::ipv6& ip,
                    const libpacket::protocol::udp&) noexcept
{
    set_ipv6_next_header(ip, traffic::protocol::ip::udp);
}

void update_length(libpacket::protocol::ipv4& ip, uint16_t length) noexcept
{
    set_ipv4_total_length(ip, length);
}

void update_length(libpacket::protocol::ipv6& ip, uint16_t length) noexcept
{
    const auto hdr_length = libpacket::protocol::ipv6::protocol_length;
    set_ipv6_payload_length(ip, length > hdr_length ? length - hdr_length : 0);
}

flags update_packet_type(flags flags, const libpacket::protocol::ipv4&) noexcept
{
    using namespace openperf::packetio::packet;
    return (flags | packet_type::ip::ipv4);
}

flags update_packet_type(flags flags, const libpacket::protocol::ipv6&) noexcept
{
    using namespace openperf::packetio::packet;
    return (flags | packet_type::ip::ipv6);
}

header_lengths update_header_lengths(header_lengths& lengths,
                                     const libpacket::protocol::ipv4&) noexcept
{
    lengths.layer3 += libpacket::protocol::ipv4::protocol_length;
    return (lengths);
}

header_lengths update_header_lengths(header_lengths& lengths,
                                     const libpacket::protocol::ipv6&) noexcept
{
    lengths.layer3 += libpacket::protocol::ipv6::protocol_length;
    return (lengths);
}

} // namespace openperf::packet::generator::traffic::protocol
