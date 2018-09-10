/**
* Inception Core API
* REST API interface to the Inception Core
*
* OpenAPI spec version: 1
* Contact: support@spirent.com
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/swagger-api/swagger-codegen.git
* Do not edit the class manually.
*/


#include "StackMemoryStats.h"

namespace icp {
namespace api {
namespace v1 {
namespace model {

StackMemoryStats::StackMemoryStats()
{
    m_Name = "";
    m_Available = 0L;
    m_Used = 0L;
    m_Max = 0L;
    m_Errors = 0L;
    m_Illegal = 0L;
    
}

StackMemoryStats::~StackMemoryStats()
{
}

void StackMemoryStats::validate()
{
    // TODO: implement validation
}

nlohmann::json StackMemoryStats::toJson() const
{
    nlohmann::json val = nlohmann::json::object();

    val["name"] = ModelBase::toJson(m_Name);
    val["available"] = m_Available;
    val["used"] = m_Used;
    val["max"] = m_Max;
    val["errors"] = m_Errors;
    val["illegal"] = m_Illegal;
    

    return val;
}

void StackMemoryStats::fromJson(nlohmann::json& val)
{
    setName(val.at("name"));
    setAvailable(val.at("available"));
    setUsed(val.at("used"));
    setMax(val.at("max"));
    setErrors(val.at("errors"));
    setIllegal(val.at("illegal"));
    
}


std::string StackMemoryStats::getName() const
{
    return m_Name;
}
void StackMemoryStats::setName(std::string value)
{
    m_Name = value;
    
}
int64_t StackMemoryStats::getAvailable() const
{
    return m_Available;
}
void StackMemoryStats::setAvailable(int64_t value)
{
    m_Available = value;
    
}
int64_t StackMemoryStats::getUsed() const
{
    return m_Used;
}
void StackMemoryStats::setUsed(int64_t value)
{
    m_Used = value;
    
}
int64_t StackMemoryStats::getMax() const
{
    return m_Max;
}
void StackMemoryStats::setMax(int64_t value)
{
    m_Max = value;
    
}
int64_t StackMemoryStats::getErrors() const
{
    return m_Errors;
}
void StackMemoryStats::setErrors(int64_t value)
{
    m_Errors = value;
    
}
int64_t StackMemoryStats::getIllegal() const
{
    return m_Illegal;
}
void StackMemoryStats::setIllegal(int64_t value)
{
    m_Illegal = value;
    
}

}
}
}
}

