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


#include "BlockGeneratorStats.h"

namespace swagger {
namespace v1 {
namespace model {

BlockGeneratorStats::BlockGeneratorStats()
{
    m_Ops_target = 0L;
    m_Ops_actual = 0L;
    m_Bytes_target = 0L;
    m_Bytes_actual = 0L;
    m_Io_errors = 0L;
    m_Latency = 0L;
    m_Latency_min = 0L;
    m_Latency_max = 0L;
    
}

BlockGeneratorStats::~BlockGeneratorStats()
{
}

void BlockGeneratorStats::validate()
{
    // TODO: implement validation
}

nlohmann::json BlockGeneratorStats::toJson() const
{
    nlohmann::json val = nlohmann::json::object();

    val["ops_target"] = m_Ops_target;
    val["ops_actual"] = m_Ops_actual;
    val["bytes_target"] = m_Bytes_target;
    val["bytes_actual"] = m_Bytes_actual;
    val["io_errors"] = m_Io_errors;
    val["latency"] = m_Latency;
    val["latency_min"] = m_Latency_min;
    val["latency_max"] = m_Latency_max;
    

    return val;
}

void BlockGeneratorStats::fromJson(nlohmann::json& val)
{
    setOpsTarget(val.at("ops_target"));
    setOpsActual(val.at("ops_actual"));
    setBytesTarget(val.at("bytes_target"));
    setBytesActual(val.at("bytes_actual"));
    setIoErrors(val.at("io_errors"));
    setLatency(val.at("latency"));
    setLatencyMin(val.at("latency_min"));
    setLatencyMax(val.at("latency_max"));
    
}


int64_t BlockGeneratorStats::getOpsTarget() const
{
    return m_Ops_target;
}
void BlockGeneratorStats::setOpsTarget(int64_t value)
{
    m_Ops_target = value;
    
}
int64_t BlockGeneratorStats::getOpsActual() const
{
    return m_Ops_actual;
}
void BlockGeneratorStats::setOpsActual(int64_t value)
{
    m_Ops_actual = value;
    
}
int64_t BlockGeneratorStats::getBytesTarget() const
{
    return m_Bytes_target;
}
void BlockGeneratorStats::setBytesTarget(int64_t value)
{
    m_Bytes_target = value;
    
}
int64_t BlockGeneratorStats::getBytesActual() const
{
    return m_Bytes_actual;
}
void BlockGeneratorStats::setBytesActual(int64_t value)
{
    m_Bytes_actual = value;
    
}
int64_t BlockGeneratorStats::getIoErrors() const
{
    return m_Io_errors;
}
void BlockGeneratorStats::setIoErrors(int64_t value)
{
    m_Io_errors = value;
    
}
int64_t BlockGeneratorStats::getLatency() const
{
    return m_Latency;
}
void BlockGeneratorStats::setLatency(int64_t value)
{
    m_Latency = value;
    
}
int64_t BlockGeneratorStats::getLatencyMin() const
{
    return m_Latency_min;
}
void BlockGeneratorStats::setLatencyMin(int64_t value)
{
    m_Latency_min = value;
    
}
int64_t BlockGeneratorStats::getLatencyMax() const
{
    return m_Latency_max;
}
void BlockGeneratorStats::setLatencyMax(int64_t value)
{
    m_Latency_max = value;
    
}

}
}
}
