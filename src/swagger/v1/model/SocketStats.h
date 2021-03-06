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
 * SocketStats.h
 *
 * Socket statistics
 */

#ifndef SocketStats_H_
#define SocketStats_H_


#include "ModelBase.h"

#include <string>

namespace swagger {
namespace v1 {
namespace model {

/// <summary>
/// Socket statistics
/// </summary>
class  SocketStats
    : public ModelBase
{
public:
    SocketStats();
    virtual ~SocketStats();

    /////////////////////////////////////////////
    /// ModelBase overrides

    void validate() override;

    nlohmann::json toJson() const override;
    void fromJson(nlohmann::json& json) override;

    /////////////////////////////////////////////
    /// SocketStats members

    /// <summary>
    /// Unique socket statistics identifier
    /// </summary>
    std::string getId() const;
    void setId(std::string value);
    bool idIsSet() const;
    void unsetId();
    /// <summary>
    /// Process ID which created the socket
    /// </summary>
    int32_t getPid() const;
    void setPid(int32_t value);
    bool pidIsSet() const;
    void unsetPid();
    /// <summary>
    /// The socket ID (used by server)
    /// </summary>
    int32_t getSid() const;
    void setSid(int32_t value);
    bool sidIsSet() const;
    void unsetSid();
    /// <summary>
    /// The interface index the socket is bound to
    /// </summary>
    int32_t getIfIndex() const;
    void setIfIndex(int32_t value);
    bool ifIndexIsSet() const;
    void unsetIf_index();
    /// <summary>
    /// The socket protocol type
    /// </summary>
    std::string getProtocol() const;
    void setProtocol(std::string value);
    bool protocolIsSet() const;
    void unsetProtocol();
    /// <summary>
    /// The protocol ID used for raw and packet sockets
    /// </summary>
    int32_t getProtocolId() const;
    void setProtocolId(int32_t value);
    bool protocolIdIsSet() const;
    void unsetProtocol_id();
    /// <summary>
    /// Number of bytes in the socket receive queue
    /// </summary>
    int64_t getRxqBytes() const;
    void setRxqBytes(int64_t value);
    bool rxqBytesIsSet() const;
    void unsetRxq_bytes();
    /// <summary>
    /// Number of bytes in the socket transmit queue
    /// </summary>
    int64_t getTxqBytes() const;
    void setTxqBytes(int64_t value);
    bool txqBytesIsSet() const;
    void unsetTxq_bytes();
    /// <summary>
    /// The local IP address
    /// </summary>
    std::string getLocalIpAddress() const;
    void setLocalIpAddress(std::string value);
    bool localIpAddressIsSet() const;
    void unsetLocal_ip_address();
    /// <summary>
    /// The remote IP address
    /// </summary>
    std::string getRemoteIpAddress() const;
    void setRemoteIpAddress(std::string value);
    bool remoteIpAddressIsSet() const;
    void unsetRemote_ip_address();
    /// <summary>
    /// The local port number
    /// </summary>
    int32_t getLocalPort() const;
    void setLocalPort(int32_t value);
    bool localPortIsSet() const;
    void unsetLocal_port();
    /// <summary>
    /// The remote port number
    /// </summary>
    int32_t getRemotePort() const;
    void setRemotePort(int32_t value);
    bool remotePortIsSet() const;
    void unsetRemote_port();
    /// <summary>
    /// The socket state
    /// </summary>
    std::string getState() const;
    void setState(std::string value);
    bool stateIsSet() const;
    void unsetState();
    /// <summary>
    /// The number of packets in the protocol send queue
    /// </summary>
    int32_t getSendQueueLength() const;
    void setSendQueueLength(int32_t value);
    bool sendQueueLengthIsSet() const;
    void unsetSend_queue_length();

protected:
    std::string m_Id;
    bool m_IdIsSet;
    int32_t m_Pid;
    bool m_PidIsSet;
    int32_t m_Sid;
    bool m_SidIsSet;
    int32_t m_If_index;
    bool m_If_indexIsSet;
    std::string m_Protocol;
    bool m_ProtocolIsSet;
    int32_t m_Protocol_id;
    bool m_Protocol_idIsSet;
    int64_t m_Rxq_bytes;
    bool m_Rxq_bytesIsSet;
    int64_t m_Txq_bytes;
    bool m_Txq_bytesIsSet;
    std::string m_Local_ip_address;
    bool m_Local_ip_addressIsSet;
    std::string m_Remote_ip_address;
    bool m_Remote_ip_addressIsSet;
    int32_t m_Local_port;
    bool m_Local_portIsSet;
    int32_t m_Remote_port;
    bool m_Remote_portIsSet;
    std::string m_State;
    bool m_StateIsSet;
    int32_t m_Send_queue_length;
    bool m_Send_queue_lengthIsSet;
};

}
}
}

#endif /* SocketStats_H_ */
