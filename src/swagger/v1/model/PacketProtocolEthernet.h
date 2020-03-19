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
 * PacketProtocolEthernet.h
 *
 * Describes an Ethernet header
 */

#ifndef PacketProtocolEthernet_H_
#define PacketProtocolEthernet_H_


#include "ModelBase.h"

#include <string>

namespace swagger {
namespace v1 {
namespace model {

/// <summary>
/// Describes an Ethernet header
/// </summary>
class  PacketProtocolEthernet
    : public ModelBase
{
public:
    PacketProtocolEthernet();
    virtual ~PacketProtocolEthernet();

    /////////////////////////////////////////////
    /// ModelBase overrides

    void validate() override;

    nlohmann::json toJson() const override;
    void fromJson(nlohmann::json& json) override;

    /////////////////////////////////////////////
    /// PacketProtocolEthernet members

    /// <summary>
    /// Ethernet MAC destination address
    /// </summary>
    std::string getDestination() const;
    void setDestination(std::string value);
    bool destinationIsSet() const;
    void unsetDestination();
    /// <summary>
    /// Ethernet ether type
    /// </summary>
    int32_t getEtherType() const;
    void setEtherType(int32_t value);
    bool etherTypeIsSet() const;
    void unsetEther_type();
    /// <summary>
    /// Ethernet MAC source address
    /// </summary>
    std::string getSource() const;
    void setSource(std::string value);
    bool sourceIsSet() const;
    void unsetSource();

protected:
    std::string m_Destination;
    bool m_DestinationIsSet;
    int32_t m_Ether_type;
    bool m_Ether_typeIsSet;
    std::string m_Source;
    bool m_SourceIsSet;
};

}
}
}

#endif /* PacketProtocolEthernet_H_ */
