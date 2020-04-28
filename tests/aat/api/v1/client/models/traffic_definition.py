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


class TrafficDefinition(object):
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
        'packet': 'TrafficPacketTemplate',
        'length': 'TrafficLength',
        'signature': 'SpirentSignature',
        'weight': 'int'
    }

    attribute_map = {
        'packet': 'packet',
        'length': 'length',
        'signature': 'signature',
        'weight': 'weight'
    }

    def __init__(self, packet=None, length=None, signature=None, weight=1):  # noqa: E501
        """TrafficDefinition - a model defined in Swagger"""  # noqa: E501

        self._packet = None
        self._length = None
        self._signature = None
        self._weight = None
        self.discriminator = None

        self.packet = packet
        self.length = length
        if signature is not None:
            self.signature = signature
        if weight is not None:
            self.weight = weight

    @property
    def packet(self):
        """Gets the packet of this TrafficDefinition.  # noqa: E501


        :return: The packet of this TrafficDefinition.  # noqa: E501
        :rtype: TrafficPacketTemplate
        """
        return self._packet

    @packet.setter
    def packet(self, packet):
        """Sets the packet of this TrafficDefinition.


        :param packet: The packet of this TrafficDefinition.  # noqa: E501
        :type: TrafficPacketTemplate
        """
        self._packet = packet

    @property
    def length(self):
        """Gets the length of this TrafficDefinition.  # noqa: E501


        :return: The length of this TrafficDefinition.  # noqa: E501
        :rtype: TrafficLength
        """
        return self._length

    @length.setter
    def length(self, length):
        """Sets the length of this TrafficDefinition.


        :param length: The length of this TrafficDefinition.  # noqa: E501
        :type: TrafficLength
        """
        self._length = length

    @property
    def signature(self):
        """Gets the signature of this TrafficDefinition.  # noqa: E501


        :return: The signature of this TrafficDefinition.  # noqa: E501
        :rtype: SpirentSignature
        """
        return self._signature

    @signature.setter
    def signature(self, signature):
        """Sets the signature of this TrafficDefinition.


        :param signature: The signature of this TrafficDefinition.  # noqa: E501
        :type: SpirentSignature
        """
        self._signature = signature

    @property
    def weight(self):
        """Gets the weight of this TrafficDefinition.  # noqa: E501

        Relative weight of this packet definition  # noqa: E501

        :return: The weight of this TrafficDefinition.  # noqa: E501
        :rtype: int
        """
        return self._weight

    @weight.setter
    def weight(self, weight):
        """Sets the weight of this TrafficDefinition.

        Relative weight of this packet definition  # noqa: E501

        :param weight: The weight of this TrafficDefinition.  # noqa: E501
        :type: int
        """
        self._weight = weight

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
        if issubclass(TrafficDefinition, dict):
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
        if not isinstance(other, TrafficDefinition):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other