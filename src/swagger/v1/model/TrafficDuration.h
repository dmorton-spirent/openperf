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
 * TrafficDuration.h
 *
 * Describes how long a packet generator should transmit traffic once started. Only one property may be set. 
 */

#ifndef TrafficDuration_H_
#define TrafficDuration_H_


#include "ModelBase.h"

#include "TrafficDuration_time.h"

namespace swagger {
namespace v1 {
namespace model {

/// <summary>
/// Describes how long a packet generator should transmit traffic once started. Only one property may be set. 
/// </summary>
class  TrafficDuration
    : public ModelBase
{
public:
    TrafficDuration();
    virtual ~TrafficDuration();

    /////////////////////////////////////////////
    /// ModelBase overrides

    void validate() override;

    nlohmann::json toJson() const override;
    void fromJson(nlohmann::json& json) override;

    /////////////////////////////////////////////
    /// TrafficDuration members

    /// <summary>
    /// Indicates there is no duration limit when set.
    /// </summary>
    bool isContinuous() const;
    void setContinuous(bool value);
    bool continuousIsSet() const;
    void unsetContinuous();
    /// <summary>
    /// Specifies the duration as number of transmitted frames.
    /// </summary>
    int32_t getFrames() const;
    void setFrames(int32_t value);
    bool framesIsSet() const;
    void unsetFrames();
    /// <summary>
    /// 
    /// </summary>
    std::shared_ptr<TrafficDuration_time> getTime() const;
    void setTime(std::shared_ptr<TrafficDuration_time> value);
    bool timeIsSet() const;
    void unsetTime();

protected:
    bool m_Continuous;
    bool m_ContinuousIsSet;
    int32_t m_Frames;
    bool m_FramesIsSet;
    std::shared_ptr<TrafficDuration_time> m_Time;
    bool m_TimeIsSet;
};

}
}
}

#endif /* TrafficDuration_H_ */