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


class ThresholdResult(object):
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
        'id': 'str',
        'value': 'float',
        'function': 'str',
        'condition': 'str',
        'stat_x': 'str',
        'stat_y': 'str',
        'condition_true': 'int',
        'condition_false': 'int'
    }

    attribute_map = {
        'id': 'id',
        'value': 'value',
        'function': 'function',
        'condition': 'condition',
        'stat_x': 'stat_x',
        'stat_y': 'stat_y',
        'condition_true': 'condition_true',
        'condition_false': 'condition_false'
    }

    def __init__(self, id=None, value=None, function=None, condition=None, stat_x=None, stat_y=None, condition_true=None, condition_false=None):  # noqa: E501
        """ThresholdResult - a model defined in Swagger"""  # noqa: E501

        self._id = None
        self._value = None
        self._function = None
        self._condition = None
        self._stat_x = None
        self._stat_y = None
        self._condition_true = None
        self._condition_false = None
        self.discriminator = None

        self.id = id
        self.value = value
        self.function = function
        self.condition = condition
        self.stat_x = stat_x
        if stat_y is not None:
            self.stat_y = stat_y
        self.condition_true = condition_true
        self.condition_false = condition_false

    @property
    def id(self):
        """Gets the id of this ThresholdResult.  # noqa: E501

        Threshold configuration unique identifier  # noqa: E501

        :return: The id of this ThresholdResult.  # noqa: E501
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this ThresholdResult.

        Threshold configuration unique identifier  # noqa: E501

        :param id: The id of this ThresholdResult.  # noqa: E501
        :type: str
        """
        self._id = id

    @property
    def value(self):
        """Gets the value of this ThresholdResult.  # noqa: E501

        The value of interest  # noqa: E501

        :return: The value of this ThresholdResult.  # noqa: E501
        :rtype: float
        """
        return self._value

    @value.setter
    def value(self, value):
        """Sets the value of this ThresholdResult.

        The value of interest  # noqa: E501

        :param value: The value of this ThresholdResult.  # noqa: E501
        :type: float
        """
        self._value = value

    @property
    def function(self):
        """Gets the function of this ThresholdResult.  # noqa: E501

        The function to apply to the statistic before evaluating  # noqa: E501

        :return: The function of this ThresholdResult.  # noqa: E501
        :rtype: str
        """
        return self._function

    @function.setter
    def function(self, function):
        """Sets the function of this ThresholdResult.

        The function to apply to the statistic before evaluating  # noqa: E501

        :param function: The function of this ThresholdResult.  # noqa: E501
        :type: str
        """
        self._function = function

    @property
    def condition(self):
        """Gets the condition of this ThresholdResult.  # noqa: E501

        The mathematical relation between value and statistic  # noqa: E501

        :return: The condition of this ThresholdResult.  # noqa: E501
        :rtype: str
        """
        return self._condition

    @condition.setter
    def condition(self, condition):
        """Sets the condition of this ThresholdResult.

        The mathematical relation between value and statistic  # noqa: E501

        :param condition: The condition of this ThresholdResult.  # noqa: E501
        :type: str
        """
        self._condition = condition

    @property
    def stat_x(self):
        """Gets the stat_x of this ThresholdResult.  # noqa: E501

        The X statistic to track  # noqa: E501

        :return: The stat_x of this ThresholdResult.  # noqa: E501
        :rtype: str
        """
        return self._stat_x

    @stat_x.setter
    def stat_x(self, stat_x):
        """Sets the stat_x of this ThresholdResult.

        The X statistic to track  # noqa: E501

        :param stat_x: The stat_x of this ThresholdResult.  # noqa: E501
        :type: str
        """
        self._stat_x = stat_x

    @property
    def stat_y(self):
        """Gets the stat_y of this ThresholdResult.  # noqa: E501

        The Y statistic to track (when using DXDY function)  # noqa: E501

        :return: The stat_y of this ThresholdResult.  # noqa: E501
        :rtype: str
        """
        return self._stat_y

    @stat_y.setter
    def stat_y(self, stat_y):
        """Sets the stat_y of this ThresholdResult.

        The Y statistic to track (when using DXDY function)  # noqa: E501

        :param stat_y: The stat_y of this ThresholdResult.  # noqa: E501
        :type: str
        """
        self._stat_y = stat_y

    @property
    def condition_true(self):
        """Gets the condition_true of this ThresholdResult.  # noqa: E501

        Counter of true conditions  # noqa: E501

        :return: The condition_true of this ThresholdResult.  # noqa: E501
        :rtype: int
        """
        return self._condition_true

    @condition_true.setter
    def condition_true(self, condition_true):
        """Sets the condition_true of this ThresholdResult.

        Counter of true conditions  # noqa: E501

        :param condition_true: The condition_true of this ThresholdResult.  # noqa: E501
        :type: int
        """
        self._condition_true = condition_true

    @property
    def condition_false(self):
        """Gets the condition_false of this ThresholdResult.  # noqa: E501

        Counter of false conditions  # noqa: E501

        :return: The condition_false of this ThresholdResult.  # noqa: E501
        :rtype: int
        """
        return self._condition_false

    @condition_false.setter
    def condition_false(self, condition_false):
        """Sets the condition_false of this ThresholdResult.

        Counter of false conditions  # noqa: E501

        :param condition_false: The condition_false of this ThresholdResult.  # noqa: E501
        :type: int
        """
        self._condition_false = condition_false

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
        if issubclass(ThresholdResult, dict):
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
        if not isinstance(other, ThresholdResult):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
