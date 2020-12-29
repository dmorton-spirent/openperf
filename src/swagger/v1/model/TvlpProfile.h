/**
* OpenPerf API
* REST API interface for OpenPerf
*
* OpenAPI spec version: 1
* Contact: support@spirent.com
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/swagger-api/swagger-codegen.git
* Do not edit the class manually.
*/
/*
 * TvlpProfile.h
 *
 * TVLP profile
 */

#ifndef TvlpProfile_H_
#define TvlpProfile_H_


#include "ModelBase.h"

#include "TvlpProfile_memory.h"
#include "TvlpProfile_network.h"
#include "TvlpProfile_block.h"
#include "TvlpProfile_cpu.h"
#include "TvlpProfile_packet.h"

namespace swagger {
namespace v1 {
namespace model {

/// <summary>
/// TVLP profile
/// </summary>
class  TvlpProfile
    : public ModelBase
{
public:
    TvlpProfile();
    virtual ~TvlpProfile();

    /////////////////////////////////////////////
    /// ModelBase overrides

    void validate() override;

    nlohmann::json toJson() const override;
    void fromJson(nlohmann::json& json) override;

    /////////////////////////////////////////////
    /// TvlpProfile members

    /// <summary>
    /// 
    /// </summary>
    std::shared_ptr<TvlpProfile_memory> getMemory() const;
    void setMemory(std::shared_ptr<TvlpProfile_memory> value);
    bool memoryIsSet() const;
    void unsetMemory();
    /// <summary>
    /// 
    /// </summary>
    std::shared_ptr<TvlpProfile_block> getBlock() const;
    void setBlock(std::shared_ptr<TvlpProfile_block> value);
    bool blockIsSet() const;
    void unsetBlock();
    /// <summary>
    /// 
    /// </summary>
    std::shared_ptr<TvlpProfile_cpu> getCpu() const;
    void setCpu(std::shared_ptr<TvlpProfile_cpu> value);
    bool cpuIsSet() const;
    void unsetCpu();
    /// <summary>
    /// 
    /// </summary>
    std::shared_ptr<TvlpProfile_packet> getPacket() const;
    void setPacket(std::shared_ptr<TvlpProfile_packet> value);
    bool packetIsSet() const;
    void unsetPacket();
    /// <summary>
    /// 
    /// </summary>
    std::shared_ptr<TvlpProfile_network> getNetwork() const;
    void setNetwork(std::shared_ptr<TvlpProfile_network> value);
    bool networkIsSet() const;
    void unsetNetwork();

protected:
    std::shared_ptr<TvlpProfile_memory> m_Memory;
    bool m_MemoryIsSet;
    std::shared_ptr<TvlpProfile_block> m_Block;
    bool m_BlockIsSet;
    std::shared_ptr<TvlpProfile_cpu> m_Cpu;
    bool m_CpuIsSet;
    std::shared_ptr<TvlpProfile_packet> m_Packet;
    bool m_PacketIsSet;
    std::shared_ptr<TvlpProfile_network> m_Network;
    bool m_NetworkIsSet;
};

}
}
}

#endif /* TvlpProfile_H_ */
