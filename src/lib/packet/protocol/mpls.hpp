#ifndef _LIB_PACKET_PROTOCOL_MPLS_HPP_
#define _LIB_PACKET_PROTOCOL_MPLS_HPP_

/**
 * MPLS header for the packet header C++ Library
 *
 * This file is automatically generated by the library code generator.
 * Do not edit this file manually.
 **/

#include <type_traits>
#include "packet/type/endian.hpp"

namespace libpacket::protocol {

struct mpls
{
    static constexpr size_t protocol_field_count = 4;
    static constexpr uint16_t protocol_length = 4;
    static constexpr std::string_view protocol_name = "mpls";

    enum class field_name
    {
        none,
        label,
        traffic_class,
        bottom_of_stack,
        ttl,
    };

    type::endian::field<3> label_traffic_class_bottom_of_stack;
    type::endian::number<uint8_t> ttl;

    static enum mpls::field_name get_field_name(std::string_view name) noexcept;
    static const std::type_info& get_field_type(field_name field) noexcept;

    template <typename Value>
    void set_field(enum field_name field, Value value) noexcept;
};

/**
 * MPLS get functions
 **/

uint32_t get_mpls_label(const mpls& header) noexcept;
uint32_t get_mpls_traffic_class(const mpls& header) noexcept;
bool get_mpls_bottom_of_stack(const mpls& header) noexcept;
uint8_t get_mpls_ttl(const mpls& header) noexcept;

/**
 * MPLS set functions
 **/

void set_mpls_label(mpls& header, uint32_t value) noexcept;
void set_mpls_traffic_class(mpls& header, uint32_t value) noexcept;
void set_mpls_bottom_of_stack(mpls& header, bool value) noexcept;
void set_mpls_ttl(mpls& header, uint8_t value) noexcept;

/**
 * MPLS generic functions
 **/

template <typename Value>
void mpls::set_field(enum mpls::field_name field, Value value) noexcept
{
    switch (field) {
        case mpls::field_name::label:
            if constexpr (std::is_convertible_v<Value, uint32_t>) {
                set_mpls_label(*this, value);
            }
            break;
        case mpls::field_name::traffic_class:
            if constexpr (std::is_convertible_v<Value, uint32_t>) {
                set_mpls_traffic_class(*this, value);
            }
            break;
        case mpls::field_name::bottom_of_stack:
            if constexpr (std::is_convertible_v<Value, uint32_t>) {
                set_mpls_bottom_of_stack(*this, static_cast<bool>(value));
            }
            break;
        case mpls::field_name::ttl:
            if constexpr (std::is_convertible_v<Value, uint8_t>) {
                set_mpls_ttl(*this, value);
            }
            break;
        default:
            break; /* no-op */
    }
}

}

#endif /* _LIB_PACKET_PROTOCOL_MPLS_HPP_ */
