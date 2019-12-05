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


#include "TimeSourceConfig.h"

namespace swagger {
namespace v1 {
namespace model {

TimeSourceConfig::TimeSourceConfig()
{
    m_NtpIsSet = false;
    
}

TimeSourceConfig::~TimeSourceConfig()
{
}

void TimeSourceConfig::validate()
{
    // TODO: implement validation
}

nlohmann::json TimeSourceConfig::toJson() const
{
    nlohmann::json val = nlohmann::json::object();

    if(m_NtpIsSet)
    {
        val["ntp"] = ModelBase::toJson(m_Ntp);
    }
    

    return val;
}

void TimeSourceConfig::fromJson(nlohmann::json& val)
{
    if(val.find("ntp") != val.end())
    {
        if(!val["ntp"].is_null())
        {
            std::shared_ptr<TimeSourceConfig_ntp> newItem(new TimeSourceConfig_ntp());
            newItem->fromJson(val["ntp"]);
            setNtp( newItem );
        }
        
    }
    
}


std::shared_ptr<TimeSourceConfig_ntp> TimeSourceConfig::getNtp() const
{
    return m_Ntp;
}
void TimeSourceConfig::setNtp(std::shared_ptr<TimeSourceConfig_ntp> value)
{
    m_Ntp = value;
    m_NtpIsSet = true;
}
bool TimeSourceConfig::ntpIsSet() const
{
    return m_NtpIsSet;
}
void TimeSourceConfig::unsetNtp()
{
    m_NtpIsSet = false;
}

}
}
}

