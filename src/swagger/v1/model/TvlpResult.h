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
 * TvlpResult.h
 *
 * TVLP result objects contain an array of generator results for each TVLP configuration step.
 */

#ifndef TvlpResult_H_
#define TvlpResult_H_


#include "ModelBase.h"

#include "NetworkGeneratorResult.h"
#include "BlockGeneratorResult.h"
#include <string>
#include "MemoryGeneratorResult.h"
#include "PacketGeneratorResult.h"
#include <vector>
#include "CpuGeneratorResult.h"

namespace swagger {
namespace v1 {
namespace model {

/// <summary>
/// TVLP result objects contain an array of generator results for each TVLP configuration step.
/// </summary>
class  TvlpResult
    : public ModelBase
{
public:
    TvlpResult();
    virtual ~TvlpResult();

    /////////////////////////////////////////////
    /// ModelBase overrides

    void validate() override;

    nlohmann::json toJson() const override;
    void fromJson(nlohmann::json& json) override;

    /////////////////////////////////////////////
    /// TvlpResult members

    /// <summary>
    /// Unique TVLP result identifier
    /// </summary>
    std::string getId() const;
    void setId(std::string value);
        /// <summary>
    /// TVLP configuration identifier that generated this result
    /// </summary>
    std::string getTvlpId() const;
    void setTvlpId(std::string value);
        /// <summary>
    /// 
    /// </summary>
    std::vector<std::shared_ptr<MemoryGeneratorResult>>& getMemory();
    bool memoryIsSet() const;
    void unsetMemory();
    /// <summary>
    /// 
    /// </summary>
    std::vector<std::shared_ptr<BlockGeneratorResult>>& getBlock();
    bool blockIsSet() const;
    void unsetBlock();
    /// <summary>
    /// 
    /// </summary>
    std::vector<std::shared_ptr<CpuGeneratorResult>>& getCpu();
    bool cpuIsSet() const;
    void unsetCpu();
    /// <summary>
    /// 
    /// </summary>
    std::vector<std::shared_ptr<PacketGeneratorResult>>& getPacket();
    bool packetIsSet() const;
    void unsetPacket();
    /// <summary>
    /// 
    /// </summary>
    std::vector<std::shared_ptr<NetworkGeneratorResult>>& getNetwork();
    bool networkIsSet() const;
    void unsetNetwork();

protected:
    std::string m_Id;

    std::string m_Tvlp_id;

    std::vector<std::shared_ptr<MemoryGeneratorResult>> m_Memory;
    bool m_MemoryIsSet;
    std::vector<std::shared_ptr<BlockGeneratorResult>> m_Block;
    bool m_BlockIsSet;
    std::vector<std::shared_ptr<CpuGeneratorResult>> m_Cpu;
    bool m_CpuIsSet;
    std::vector<std::shared_ptr<PacketGeneratorResult>> m_Packet;
    bool m_PacketIsSet;
    std::vector<std::shared_ptr<NetworkGeneratorResult>> m_Network;
    bool m_NetworkIsSet;
};

}
}
}

#endif /* TvlpResult_H_ */
