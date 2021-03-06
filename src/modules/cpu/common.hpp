#ifndef _OP_CPU_COMMON_HPP_
#define _OP_CPU_COMMON_HPP_

#include <optional>
#include <string_view>
#include <variant>
#include <vector>

#include "instruction_set.hpp"

namespace openperf::cpu {

enum class data_type { INT32 = 1, INT64, FLOAT32, FLOAT64 };

struct target_config
{
    instruction_set::type set;
    data_type data_type;
    uint64_t weight;
};

struct task_cpu_config
{
    double utilization = 0.0;
    uint16_t core = 0;
    std::vector<target_config> targets;
};

using cores_config = std::vector<task_cpu_config>;
using generator_config = std::variant<double, cores_config>;

constexpr data_type to_data_type(std::string_view value)
{
    if (value == "int32") return data_type::INT32;
    if (value == "int64") return data_type::INT64;
    if (value == "float32") return data_type::FLOAT32;
    if (value == "float64") return data_type::FLOAT64;

    throw std::runtime_error(
        "Error from string to data_type converting: Illegal string value");
}

constexpr std::string_view to_string(data_type value)
{
    switch (value) {
    case data_type::INT32:
        return "int32";
    case data_type::INT64:
        return "int64";
    case data_type::FLOAT32:
        return "float32";
    case data_type::FLOAT64:
        return "float64";
    default:
        return "unknown";
    };
}

} // namespace openperf::cpu

#endif // _OP_CPU_COMMON_HPP_
