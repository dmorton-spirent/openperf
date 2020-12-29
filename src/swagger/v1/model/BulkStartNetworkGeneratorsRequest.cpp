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


#include "BulkStartNetworkGeneratorsRequest.h"

namespace swagger {
namespace v1 {
namespace model {

BulkStartNetworkGeneratorsRequest::BulkStartNetworkGeneratorsRequest()
{
    m_Dynamic_resultsIsSet = false;
    
}

BulkStartNetworkGeneratorsRequest::~BulkStartNetworkGeneratorsRequest()
{
}

void BulkStartNetworkGeneratorsRequest::validate()
{
    // TODO: implement validation
}

nlohmann::json BulkStartNetworkGeneratorsRequest::toJson() const
{
    nlohmann::json val = nlohmann::json::object();

    {
        nlohmann::json jsonArray;
        for( auto& item : m_Ids )
        {
            jsonArray.push_back(ModelBase::toJson(item));
        }
        val["ids"] = jsonArray;
            }
    if(m_Dynamic_resultsIsSet)
    {
        val["dynamic_results"] = ModelBase::toJson(m_Dynamic_results);
    }
    

    return val;
}

void BulkStartNetworkGeneratorsRequest::fromJson(nlohmann::json& val)
{
    {
        m_Ids.clear();
        nlohmann::json jsonArray;
                for( auto& item : val["ids"] )
        {
            m_Ids.push_back(item);
            
        }
    }
    if(val.find("dynamic_results") != val.end())
    {
        if(!val["dynamic_results"].is_null())
        {
            std::shared_ptr<DynamicResultsConfig> newItem(new DynamicResultsConfig());
            newItem->fromJson(val["dynamic_results"]);
            setDynamicResults( newItem );
        }
        
    }
    
}


std::vector<std::string>& BulkStartNetworkGeneratorsRequest::getIds()
{
    return m_Ids;
}
std::shared_ptr<DynamicResultsConfig> BulkStartNetworkGeneratorsRequest::getDynamicResults() const
{
    return m_Dynamic_results;
}
void BulkStartNetworkGeneratorsRequest::setDynamicResults(std::shared_ptr<DynamicResultsConfig> value)
{
    m_Dynamic_results = value;
    m_Dynamic_resultsIsSet = true;
}
bool BulkStartNetworkGeneratorsRequest::dynamicResultsIsSet() const
{
    return m_Dynamic_resultsIsSet;
}
void BulkStartNetworkGeneratorsRequest::unsetDynamic_results()
{
    m_Dynamic_resultsIsSet = false;
}

}
}
}

