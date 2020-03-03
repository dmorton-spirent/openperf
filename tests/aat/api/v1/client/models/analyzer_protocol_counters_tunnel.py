# coding: utf-8

"""
    OpenPerf API

    REST API interface for OpenPerf  # noqa: E501

    OpenAPI spec version: 1
    Contact: support@spirent.com
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


import pprint
import re  # noqa: F401

import six


class AnalyzerProtocolCountersTunnel(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    """

    """
    Attributes:
      swagger_types (dict): The key is attribute name
                            and the value is attribute type.
      attribute_map (dict): The key is attribute name
                            and the value is json key in definition.
    """
    swagger_types = {
        'ip': 'int',
        'gre': 'int',
        'vxlan': 'int',
        'nvgre': 'int',
        'geneve': 'int',
        'grenat': 'int',
        'gtpc': 'int',
        'gtpu': 'int',
        'esp': 'int',
        'l2tp': 'int',
        'vxlan_gpe': 'int',
        'mpls_in_gre': 'int',
        'mpls_in_udp': 'int'
    }

    attribute_map = {
        'ip': 'ip',
        'gre': 'gre',
        'vxlan': 'vxlan',
        'nvgre': 'nvgre',
        'geneve': 'geneve',
        'grenat': 'grenat',
        'gtpc': 'gtpc',
        'gtpu': 'gtpu',
        'esp': 'esp',
        'l2tp': 'l2tp',
        'vxlan_gpe': 'vxlan_gpe',
        'mpls_in_gre': 'mpls_in_gre',
        'mpls_in_udp': 'mpls_in_udp'
    }

    def __init__(self, ip=None, gre=None, vxlan=None, nvgre=None, geneve=None, grenat=None, gtpc=None, gtpu=None, esp=None, l2tp=None, vxlan_gpe=None, mpls_in_gre=None, mpls_in_udp=None):  # noqa: E501
        """AnalyzerProtocolCountersTunnel - a model defined in Swagger"""  # noqa: E501

        self._ip = None
        self._gre = None
        self._vxlan = None
        self._nvgre = None
        self._geneve = None
        self._grenat = None
        self._gtpc = None
        self._gtpu = None
        self._esp = None
        self._l2tp = None
        self._vxlan_gpe = None
        self._mpls_in_gre = None
        self._mpls_in_udp = None
        self.discriminator = None

        self.ip = ip
        self.gre = gre
        self.vxlan = vxlan
        self.nvgre = nvgre
        self.geneve = geneve
        self.grenat = grenat
        self.gtpc = gtpc
        self.gtpu = gtpu
        self.esp = esp
        self.l2tp = l2tp
        self.vxlan_gpe = vxlan_gpe
        self.mpls_in_gre = mpls_in_gre
        self.mpls_in_udp = mpls_in_udp

    @property
    def ip(self):
        """Gets the ip of this AnalyzerProtocolCountersTunnel.  # noqa: E501

        Number of IP in IP packets  # noqa: E501

        :return: The ip of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :rtype: int
        """
        return self._ip

    @ip.setter
    def ip(self, ip):
        """Sets the ip of this AnalyzerProtocolCountersTunnel.

        Number of IP in IP packets  # noqa: E501

        :param ip: The ip of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :type: int
        """
        self._ip = ip

    @property
    def gre(self):
        """Gets the gre of this AnalyzerProtocolCountersTunnel.  # noqa: E501

        Number of Generic Routing Encapsulation packets  # noqa: E501

        :return: The gre of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :rtype: int
        """
        return self._gre

    @gre.setter
    def gre(self, gre):
        """Sets the gre of this AnalyzerProtocolCountersTunnel.

        Number of Generic Routing Encapsulation packets  # noqa: E501

        :param gre: The gre of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :type: int
        """
        self._gre = gre

    @property
    def vxlan(self):
        """Gets the vxlan of this AnalyzerProtocolCountersTunnel.  # noqa: E501

        Number of Virtual eXtensible LAN packets  # noqa: E501

        :return: The vxlan of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :rtype: int
        """
        return self._vxlan

    @vxlan.setter
    def vxlan(self, vxlan):
        """Sets the vxlan of this AnalyzerProtocolCountersTunnel.

        Number of Virtual eXtensible LAN packets  # noqa: E501

        :param vxlan: The vxlan of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :type: int
        """
        self._vxlan = vxlan

    @property
    def nvgre(self):
        """Gets the nvgre of this AnalyzerProtocolCountersTunnel.  # noqa: E501

        Number of Network Virtualization using GRE packets  # noqa: E501

        :return: The nvgre of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :rtype: int
        """
        return self._nvgre

    @nvgre.setter
    def nvgre(self, nvgre):
        """Sets the nvgre of this AnalyzerProtocolCountersTunnel.

        Number of Network Virtualization using GRE packets  # noqa: E501

        :param nvgre: The nvgre of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :type: int
        """
        self._nvgre = nvgre

    @property
    def geneve(self):
        """Gets the geneve of this AnalyzerProtocolCountersTunnel.  # noqa: E501

        Number of Generic Network Virtualization Encapsulation packets  # noqa: E501

        :return: The geneve of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :rtype: int
        """
        return self._geneve

    @geneve.setter
    def geneve(self, geneve):
        """Sets the geneve of this AnalyzerProtocolCountersTunnel.

        Number of Generic Network Virtualization Encapsulation packets  # noqa: E501

        :param geneve: The geneve of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :type: int
        """
        self._geneve = geneve

    @property
    def grenat(self):
        """Gets the grenat of this AnalyzerProtocolCountersTunnel.  # noqa: E501

        Number of Teredo, VXLAN, or GRE packets on limited hardware  # noqa: E501

        :return: The grenat of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :rtype: int
        """
        return self._grenat

    @grenat.setter
    def grenat(self, grenat):
        """Sets the grenat of this AnalyzerProtocolCountersTunnel.

        Number of Teredo, VXLAN, or GRE packets on limited hardware  # noqa: E501

        :param grenat: The grenat of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :type: int
        """
        self._grenat = grenat

    @property
    def gtpc(self):
        """Gets the gtpc of this AnalyzerProtocolCountersTunnel.  # noqa: E501

        Number of GPRS Tunneling Protocol control packets  # noqa: E501

        :return: The gtpc of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :rtype: int
        """
        return self._gtpc

    @gtpc.setter
    def gtpc(self, gtpc):
        """Sets the gtpc of this AnalyzerProtocolCountersTunnel.

        Number of GPRS Tunneling Protocol control packets  # noqa: E501

        :param gtpc: The gtpc of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :type: int
        """
        self._gtpc = gtpc

    @property
    def gtpu(self):
        """Gets the gtpu of this AnalyzerProtocolCountersTunnel.  # noqa: E501

        Number of GPRS Tunneling Protocol user packets  # noqa: E501

        :return: The gtpu of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :rtype: int
        """
        return self._gtpu

    @gtpu.setter
    def gtpu(self, gtpu):
        """Sets the gtpu of this AnalyzerProtocolCountersTunnel.

        Number of GPRS Tunneling Protocol user packets  # noqa: E501

        :param gtpu: The gtpu of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :type: int
        """
        self._gtpu = gtpu

    @property
    def esp(self):
        """Gets the esp of this AnalyzerProtocolCountersTunnel.  # noqa: E501

        Number of IP Encapsulating Security Payload packets  # noqa: E501

        :return: The esp of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :rtype: int
        """
        return self._esp

    @esp.setter
    def esp(self, esp):
        """Sets the esp of this AnalyzerProtocolCountersTunnel.

        Number of IP Encapsulating Security Payload packets  # noqa: E501

        :param esp: The esp of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :type: int
        """
        self._esp = esp

    @property
    def l2tp(self):
        """Gets the l2tp of this AnalyzerProtocolCountersTunnel.  # noqa: E501

        Number of Layer 2 Tunneling Protocol packets  # noqa: E501

        :return: The l2tp of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :rtype: int
        """
        return self._l2tp

    @l2tp.setter
    def l2tp(self, l2tp):
        """Sets the l2tp of this AnalyzerProtocolCountersTunnel.

        Number of Layer 2 Tunneling Protocol packets  # noqa: E501

        :param l2tp: The l2tp of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :type: int
        """
        self._l2tp = l2tp

    @property
    def vxlan_gpe(self):
        """Gets the vxlan_gpe of this AnalyzerProtocolCountersTunnel.  # noqa: E501

        Number of VXLAN Generic Protocol Extension packets  # noqa: E501

        :return: The vxlan_gpe of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :rtype: int
        """
        return self._vxlan_gpe

    @vxlan_gpe.setter
    def vxlan_gpe(self, vxlan_gpe):
        """Sets the vxlan_gpe of this AnalyzerProtocolCountersTunnel.

        Number of VXLAN Generic Protocol Extension packets  # noqa: E501

        :param vxlan_gpe: The vxlan_gpe of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :type: int
        """
        self._vxlan_gpe = vxlan_gpe

    @property
    def mpls_in_gre(self):
        """Gets the mpls_in_gre of this AnalyzerProtocolCountersTunnel.  # noqa: E501

        Number of MPLS-in-GRE packets (RFC 4023)  # noqa: E501

        :return: The mpls_in_gre of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :rtype: int
        """
        return self._mpls_in_gre

    @mpls_in_gre.setter
    def mpls_in_gre(self, mpls_in_gre):
        """Sets the mpls_in_gre of this AnalyzerProtocolCountersTunnel.

        Number of MPLS-in-GRE packets (RFC 4023)  # noqa: E501

        :param mpls_in_gre: The mpls_in_gre of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :type: int
        """
        self._mpls_in_gre = mpls_in_gre

    @property
    def mpls_in_udp(self):
        """Gets the mpls_in_udp of this AnalyzerProtocolCountersTunnel.  # noqa: E501

        Number of MPLS-in-UDP packets (RFC 7510)  # noqa: E501

        :return: The mpls_in_udp of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :rtype: int
        """
        return self._mpls_in_udp

    @mpls_in_udp.setter
    def mpls_in_udp(self, mpls_in_udp):
        """Sets the mpls_in_udp of this AnalyzerProtocolCountersTunnel.

        Number of MPLS-in-UDP packets (RFC 7510)  # noqa: E501

        :param mpls_in_udp: The mpls_in_udp of this AnalyzerProtocolCountersTunnel.  # noqa: E501
        :type: int
        """
        self._mpls_in_udp = mpls_in_udp

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value
        if issubclass(AnalyzerProtocolCountersTunnel, dict):
            for key, value in self.items():
                result[key] = value

        return result

    def to_str(self):
        """Returns the string representation of the model"""
        return pprint.pformat(self.to_dict())

    def __repr__(self):
        """For `print` and `pprint`"""
        return self.to_str()

    def __eq__(self, other):
        """Returns true if both objects are equal"""
        if not isinstance(other, AnalyzerProtocolCountersTunnel):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
