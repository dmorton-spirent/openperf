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
 * TimeKeeperStats_round_trip_times.h
 *
 * The round trip time measures the total elapsed time to make a timestamp exchange with the remote time source.  The TimeKeeper stores RTT data so that the least delayed clock exchanges can be given extra weight when calculating the current clock offset. 
 */

#ifndef TimeKeeperStats_round_trip_times_H_
#define TimeKeeperStats_round_trip_times_H_


#include "ModelBase.h"


namespace swagger {
namespace v1 {
namespace model {

/// <summary>
/// The round trip time measures the total elapsed time to make a timestamp exchange with the remote time source.  The TimeKeeper stores RTT data so that the least delayed clock exchanges can be given extra weight when calculating the current clock offset. 
/// </summary>
class  TimeKeeperStats_round_trip_times
    : public ModelBase
{
public:
    TimeKeeperStats_round_trip_times();
    virtual ~TimeKeeperStats_round_trip_times();

    /////////////////////////////////////////////
    /// ModelBase overrides

    void validate() override;

    nlohmann::json toJson() const override;
    void fromJson(nlohmann::json& json) override;

    /////////////////////////////////////////////
    /// TimeKeeperStats_round_trip_times members

    /// <summary>
    /// the average round trip time, in seconds.
    /// </summary>
    double getAvg() const;
    void setAvg(double value);
    bool avgIsSet() const;
    void unsetAvg();
    /// <summary>
    /// The maximum round trip time, in seconds.
    /// </summary>
    double getMax() const;
    void setMax(double value);
    bool maxIsSet() const;
    void unsetMax();
    /// <summary>
    /// The minimum round trip time, in seconds.
    /// </summary>
    double getMin() const;
    void setMin(double value);
    bool minIsSet() const;
    void unsetMin();
    /// <summary>
    /// The number of round trip times in the data set.
    /// </summary>
    int64_t getSize() const;
    void setSize(int64_t value);
    
protected:
    double m_Avg;
    bool m_AvgIsSet;
    double m_Max;
    bool m_MaxIsSet;
    double m_Min;
    bool m_MinIsSet;
    int64_t m_Size;

};

}
}
}

#endif /* TimeKeeperStats_round_trip_times_H_ */
