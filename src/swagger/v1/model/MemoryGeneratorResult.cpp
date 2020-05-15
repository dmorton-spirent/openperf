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


#include "MemoryGeneratorResult.h"

namespace swagger {
namespace v1 {
namespace model {

MemoryGeneratorResult::MemoryGeneratorResult()
{
    m_Id = "";
    m_Generator_id = "";
    m_Generator_idIsSet = false;
    m_Active = false;
    m_Timestamp = "";
    
}

MemoryGeneratorResult::~MemoryGeneratorResult()
{
}

void MemoryGeneratorResult::validate()
{
    // TODO: implement validation
}

nlohmann::json MemoryGeneratorResult::toJson() const
{
    nlohmann::json val = nlohmann::json::object();

    val["id"] = ModelBase::toJson(m_Id);
    if(m_Generator_idIsSet)
    {
        val["generator_id"] = ModelBase::toJson(m_Generator_id);
    }
    val["active"] = m_Active;
    val["timestamp"] = ModelBase::toJson(m_Timestamp);
    val["read"] = ModelBase::toJson(m_Read);
    val["write"] = ModelBase::toJson(m_Write);
    

    return val;
}

void MemoryGeneratorResult::fromJson(nlohmann::json& val)
{
    setId(val.at("id"));
    if(val.find("generator_id") != val.end())
    {
        setGeneratorId(val.at("generator_id"));
        
    }
    setActive(val.at("active"));
    setTimestamp(val.at("timestamp"));
    
}


std::string MemoryGeneratorResult::getId() const
{
    return m_Id;
}
void MemoryGeneratorResult::setId(std::string value)
{
    m_Id = value;
    
}
std::string MemoryGeneratorResult::getGeneratorId() const
{
    return m_Generator_id;
}
void MemoryGeneratorResult::setGeneratorId(std::string value)
{
    m_Generator_id = value;
    m_Generator_idIsSet = true;
}
bool MemoryGeneratorResult::generatorIdIsSet() const
{
    return m_Generator_idIsSet;
}
void MemoryGeneratorResult::unsetGenerator_id()
{
    m_Generator_idIsSet = false;
}
bool MemoryGeneratorResult::isActive() const
{
    return m_Active;
}
void MemoryGeneratorResult::setActive(bool value)
{
    m_Active = value;
    
}
std::string MemoryGeneratorResult::getTimestamp() const
{
    return m_Timestamp;
}
void MemoryGeneratorResult::setTimestamp(std::string value)
{
    m_Timestamp = value;
    
}
std::shared_ptr<MemoryGeneratorStats> MemoryGeneratorResult::getRead() const
{
    return m_Read;
}
void MemoryGeneratorResult::setRead(std::shared_ptr<MemoryGeneratorStats> value)
{
    m_Read = value;
    
}
std::shared_ptr<MemoryGeneratorStats> MemoryGeneratorResult::getWrite() const
{
    return m_Write;
}
void MemoryGeneratorResult::setWrite(std::shared_ptr<MemoryGeneratorStats> value)
{
    m_Write = value;
    
}

}
}
}
