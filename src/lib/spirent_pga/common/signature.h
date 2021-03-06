#ifndef _LIB_SPIRENT_PGA_SIGNATURE_H_
#define _LIB_SPIRENT_PGA_SIGNATURE_H_

#include <cstdint>

namespace pga::signature {

uint16_t
crc_filter(const uint8_t* const payloads[], uint16_t count, int crc_matches[]);

uint16_t decode(const uint8_t* const payloads[],
                uint16_t count,
                uint32_t stream_ids[],
                uint32_t sequence_numbers[],
                uint64_t timestamps[],
                int flags[]);

void encode(uint8_t* destinations[],
            const uint32_t stream_ids[],
            const uint32_t sequence_numbers[],
            const uint64_t timestamps[],
            const int flags[],
            uint16_t count);

} // namespace pga::signature

#endif /* _LIB_SPIRENT_PGA_SIGNATURE_H_ */
