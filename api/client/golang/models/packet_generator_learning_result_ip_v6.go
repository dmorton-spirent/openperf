// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// PacketGeneratorLearningResultIPV6 Defines an IPv6 destination address, IPv6 next hop address,  next hop MAC address tuple.
//
// swagger:model PacketGeneratorLearningResultIpv6
type PacketGeneratorLearningResultIPV6 struct {

	// IPv6 destination address.
	// Required: true
	// Pattern: ^((::[0-9a-fA-F]{1,4})|([0-9a-fA-F]{1,4}::)|(([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F])|(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}))$
	IPAddress *string `json:"ip_address"`

	// MAC address of next hop IPv6 address.
	MacAddress string `json:"mac_address,omitempty"`

	// IPv6 next hop address.
	// Pattern: ^((::[0-9a-fA-F]{1,4})|([0-9a-fA-F]{1,4}::)|(([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F])|(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}))$
	NextHopAddress string `json:"next_hop_address,omitempty"`
}

// Validate validates this packet generator learning result Ipv6
func (m *PacketGeneratorLearningResultIPV6) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateIPAddress(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNextHopAddress(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PacketGeneratorLearningResultIPV6) validateIPAddress(formats strfmt.Registry) error {

	if err := validate.Required("ip_address", "body", m.IPAddress); err != nil {
		return err
	}

	if err := validate.Pattern("ip_address", "body", *m.IPAddress, `^((::[0-9a-fA-F]{1,4})|([0-9a-fA-F]{1,4}::)|(([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F])|(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}))$`); err != nil {
		return err
	}

	return nil
}

func (m *PacketGeneratorLearningResultIPV6) validateNextHopAddress(formats strfmt.Registry) error {
	if swag.IsZero(m.NextHopAddress) { // not required
		return nil
	}

	if err := validate.Pattern("next_hop_address", "body", m.NextHopAddress, `^((::[0-9a-fA-F]{1,4})|([0-9a-fA-F]{1,4}::)|(([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F])|(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}))$`); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this packet generator learning result Ipv6 based on context it is used
func (m *PacketGeneratorLearningResultIPV6) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *PacketGeneratorLearningResultIPV6) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PacketGeneratorLearningResultIPV6) UnmarshalBinary(b []byte) error {
	var res PacketGeneratorLearningResultIPV6
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}