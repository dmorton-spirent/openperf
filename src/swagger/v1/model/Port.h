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
 * Port.h
 *
 * Physical port or port-equivalent (e.g. bonded ports)
 */

#ifndef Port_H_
#define Port_H_


#include "ModelBase.h"

#include "PortStatus.h"
#include "PortConfig.h"
#include "PortStats.h"
#include <string>

namespace swagger {
namespace v1 {
namespace model {

/// <summary>
/// Physical port or port-equivalent (e.g. bonded ports)
/// </summary>
class  Port
    : public ModelBase
{
public:
    Port();
    virtual ~Port();

    /////////////////////////////////////////////
    /// ModelBase overrides

    void validate() override;

    nlohmann::json toJson() const override;
    void fromJson(nlohmann::json& json) override;

    /////////////////////////////////////////////
    /// Port members

    /// <summary>
    /// Unique port identifier
    /// </summary>
    std::string getId() const;
    void setId(std::string value);
        /// <summary>
    /// Port kind
    /// </summary>
    std::string getKind() const;
    void setKind(std::string value);
        /// <summary>
    /// 
    /// </summary>
    std::shared_ptr<PortConfig> getConfig() const;
    void setConfig(std::shared_ptr<PortConfig> value);
        /// <summary>
    /// 
    /// </summary>
    std::shared_ptr<PortStatus> getStatus() const;
    void setStatus(std::shared_ptr<PortStatus> value);
        /// <summary>
    /// 
    /// </summary>
    std::shared_ptr<PortStats> getStats() const;
    void setStats(std::shared_ptr<PortStats> value);
    
protected:
    std::string m_Id;

    std::string m_Kind;

    std::shared_ptr<PortConfig> m_Config;

    std::shared_ptr<PortStatus> m_Status;

    std::shared_ptr<PortStats> m_Stats;

};

}
}
}

#endif /* Port_H_ */
