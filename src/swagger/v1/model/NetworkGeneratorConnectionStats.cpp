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


#include "NetworkGeneratorConnectionStats.h"

namespace swagger {
namespace v1 {
namespace model {

NetworkGeneratorConnectionStats::NetworkGeneratorConnectionStats()
{
    m_Attempted = 0L;
    m_Successful = 0L;
    m_Errors = 0L;
    m_Closed = 0L;
    
}

NetworkGeneratorConnectionStats::~NetworkGeneratorConnectionStats()
{
}

void NetworkGeneratorConnectionStats::validate()
{
    // TODO: implement validation
}

nlohmann::json NetworkGeneratorConnectionStats::toJson() const
{
    nlohmann::json val = nlohmann::json::object();

    val["attempted"] = m_Attempted;
    val["successful"] = m_Successful;
    val["errors"] = m_Errors;
    val["closed"] = m_Closed;
    

    return val;
}

void NetworkGeneratorConnectionStats::fromJson(nlohmann::json& val)
{
    setAttempted(val.at("attempted"));
    setSuccessful(val.at("successful"));
    setErrors(val.at("errors"));
    setClosed(val.at("closed"));
    
}


int64_t NetworkGeneratorConnectionStats::getAttempted() const
{
    return m_Attempted;
}
void NetworkGeneratorConnectionStats::setAttempted(int64_t value)
{
    m_Attempted = value;
    
}
int64_t NetworkGeneratorConnectionStats::getSuccessful() const
{
    return m_Successful;
}
void NetworkGeneratorConnectionStats::setSuccessful(int64_t value)
{
    m_Successful = value;
    
}
int64_t NetworkGeneratorConnectionStats::getErrors() const
{
    return m_Errors;
}
void NetworkGeneratorConnectionStats::setErrors(int64_t value)
{
    m_Errors = value;
    
}
int64_t NetworkGeneratorConnectionStats::getClosed() const
{
    return m_Closed;
}
void NetworkGeneratorConnectionStats::setClosed(int64_t value)
{
    m_Closed = value;
    
}

}
}
}

