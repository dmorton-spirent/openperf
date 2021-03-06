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


class InterfaceProtocolConfig(object):
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
        'eth': 'InterfaceProtocolConfigEth',
        'ipv4': 'InterfaceProtocolConfigIpv4',
        'ipv6': 'InterfaceProtocolConfigIpv6'
    }

    attribute_map = {
        'eth': 'eth',
        'ipv4': 'ipv4',
        'ipv6': 'ipv6'
    }

    def __init__(self, eth=None, ipv4=None, ipv6=None):  # noqa: E501
        """InterfaceProtocolConfig - a model defined in Swagger"""  # noqa: E501

        self._eth = None
        self._ipv4 = None
        self._ipv6 = None
        self.discriminator = None

        if eth is not None:
            self.eth = eth
        if ipv4 is not None:
            self.ipv4 = ipv4
        if ipv6 is not None:
            self.ipv6 = ipv6

    @property
    def eth(self):
        """Gets the eth of this InterfaceProtocolConfig.  # noqa: E501


        :return: The eth of this InterfaceProtocolConfig.  # noqa: E501
        :rtype: InterfaceProtocolConfigEth
        """
        return self._eth

    @eth.setter
    def eth(self, eth):
        """Sets the eth of this InterfaceProtocolConfig.


        :param eth: The eth of this InterfaceProtocolConfig.  # noqa: E501
        :type: InterfaceProtocolConfigEth
        """
        self._eth = eth

    @property
    def ipv4(self):
        """Gets the ipv4 of this InterfaceProtocolConfig.  # noqa: E501


        :return: The ipv4 of this InterfaceProtocolConfig.  # noqa: E501
        :rtype: InterfaceProtocolConfigIpv4
        """
        return self._ipv4

    @ipv4.setter
    def ipv4(self, ipv4):
        """Sets the ipv4 of this InterfaceProtocolConfig.


        :param ipv4: The ipv4 of this InterfaceProtocolConfig.  # noqa: E501
        :type: InterfaceProtocolConfigIpv4
        """
        self._ipv4 = ipv4

    @property
    def ipv6(self):
        """Gets the ipv6 of this InterfaceProtocolConfig.  # noqa: E501


        :return: The ipv6 of this InterfaceProtocolConfig.  # noqa: E501
        :rtype: InterfaceProtocolConfigIpv6
        """
        return self._ipv6

    @ipv6.setter
    def ipv6(self, ipv6):
        """Sets the ipv6 of this InterfaceProtocolConfig.


        :param ipv6: The ipv6 of this InterfaceProtocolConfig.  # noqa: E501
        :type: InterfaceProtocolConfigIpv6
        """
        self._ipv6 = ipv6

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
        if issubclass(InterfaceProtocolConfig, dict):
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
        if not isinstance(other, InterfaceProtocolConfig):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
