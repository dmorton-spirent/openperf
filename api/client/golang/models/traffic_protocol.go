// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// TrafficProtocol A traffic protocol definition for a traffic generator. At least one
// packet protocol must be set.
//
//
// swagger:model TrafficProtocol
type TrafficProtocol struct {

	// custom
	Custom *PacketProtocolCustom `json:"custom,omitempty"`

	// ethernet
	Ethernet *PacketProtocolEthernet `json:"ethernet,omitempty"`

	// ipv4
	IPV4 *PacketProtocolIPV4 `json:"ipv4,omitempty"`

	// ipv6
	IPV6 *PacketProtocolIPV6 `json:"ipv6,omitempty"`

	// modifiers
	Modifiers *TrafficProtocolModifiers `json:"modifiers,omitempty"`

	// mpls
	Mpls *PacketProtocolMpls `json:"mpls,omitempty"`

	// tcp
	TCP *PacketProtocolTCP `json:"tcp,omitempty"`

	// udp
	UDP *PacketProtocolUDP `json:"udp,omitempty"`

	// vlan
	Vlan *PacketProtocolVlan `json:"vlan,omitempty"`
}

// Validate validates this traffic protocol
func (m *TrafficProtocol) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCustom(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEthernet(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIPV4(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIPV6(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateModifiers(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMpls(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTCP(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUDP(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVlan(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TrafficProtocol) validateCustom(formats strfmt.Registry) error {
	if swag.IsZero(m.Custom) { // not required
		return nil
	}

	if m.Custom != nil {
		if err := m.Custom.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("custom")
			}
			return err
		}
	}

	return nil
}

func (m *TrafficProtocol) validateEthernet(formats strfmt.Registry) error {
	if swag.IsZero(m.Ethernet) { // not required
		return nil
	}

	if m.Ethernet != nil {
		if err := m.Ethernet.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ethernet")
			}
			return err
		}
	}

	return nil
}

func (m *TrafficProtocol) validateIPV4(formats strfmt.Registry) error {
	if swag.IsZero(m.IPV4) { // not required
		return nil
	}

	if m.IPV4 != nil {
		if err := m.IPV4.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ipv4")
			}
			return err
		}
	}

	return nil
}

func (m *TrafficProtocol) validateIPV6(formats strfmt.Registry) error {
	if swag.IsZero(m.IPV6) { // not required
		return nil
	}

	if m.IPV6 != nil {
		if err := m.IPV6.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ipv6")
			}
			return err
		}
	}

	return nil
}

func (m *TrafficProtocol) validateModifiers(formats strfmt.Registry) error {
	if swag.IsZero(m.Modifiers) { // not required
		return nil
	}

	if m.Modifiers != nil {
		if err := m.Modifiers.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("modifiers")
			}
			return err
		}
	}

	return nil
}

func (m *TrafficProtocol) validateMpls(formats strfmt.Registry) error {
	if swag.IsZero(m.Mpls) { // not required
		return nil
	}

	if m.Mpls != nil {
		if err := m.Mpls.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("mpls")
			}
			return err
		}
	}

	return nil
}

func (m *TrafficProtocol) validateTCP(formats strfmt.Registry) error {
	if swag.IsZero(m.TCP) { // not required
		return nil
	}

	if m.TCP != nil {
		if err := m.TCP.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("tcp")
			}
			return err
		}
	}

	return nil
}

func (m *TrafficProtocol) validateUDP(formats strfmt.Registry) error {
	if swag.IsZero(m.UDP) { // not required
		return nil
	}

	if m.UDP != nil {
		if err := m.UDP.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("udp")
			}
			return err
		}
	}

	return nil
}

func (m *TrafficProtocol) validateVlan(formats strfmt.Registry) error {
	if swag.IsZero(m.Vlan) { // not required
		return nil
	}

	if m.Vlan != nil {
		if err := m.Vlan.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("vlan")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this traffic protocol based on the context it is used
func (m *TrafficProtocol) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCustom(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateEthernet(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateIPV4(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateIPV6(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateModifiers(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMpls(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTCP(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateUDP(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateVlan(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TrafficProtocol) contextValidateCustom(ctx context.Context, formats strfmt.Registry) error {

	if m.Custom != nil {
		if err := m.Custom.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("custom")
			}
			return err
		}
	}

	return nil
}

func (m *TrafficProtocol) contextValidateEthernet(ctx context.Context, formats strfmt.Registry) error {

	if m.Ethernet != nil {
		if err := m.Ethernet.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ethernet")
			}
			return err
		}
	}

	return nil
}

func (m *TrafficProtocol) contextValidateIPV4(ctx context.Context, formats strfmt.Registry) error {

	if m.IPV4 != nil {
		if err := m.IPV4.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ipv4")
			}
			return err
		}
	}

	return nil
}

func (m *TrafficProtocol) contextValidateIPV6(ctx context.Context, formats strfmt.Registry) error {

	if m.IPV6 != nil {
		if err := m.IPV6.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ipv6")
			}
			return err
		}
	}

	return nil
}

func (m *TrafficProtocol) contextValidateModifiers(ctx context.Context, formats strfmt.Registry) error {

	if m.Modifiers != nil {
		if err := m.Modifiers.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("modifiers")
			}
			return err
		}
	}

	return nil
}

func (m *TrafficProtocol) contextValidateMpls(ctx context.Context, formats strfmt.Registry) error {

	if m.Mpls != nil {
		if err := m.Mpls.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("mpls")
			}
			return err
		}
	}

	return nil
}

func (m *TrafficProtocol) contextValidateTCP(ctx context.Context, formats strfmt.Registry) error {

	if m.TCP != nil {
		if err := m.TCP.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("tcp")
			}
			return err
		}
	}

	return nil
}

func (m *TrafficProtocol) contextValidateUDP(ctx context.Context, formats strfmt.Registry) error {

	if m.UDP != nil {
		if err := m.UDP.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("udp")
			}
			return err
		}
	}

	return nil
}

func (m *TrafficProtocol) contextValidateVlan(ctx context.Context, formats strfmt.Registry) error {

	if m.Vlan != nil {
		if err := m.Vlan.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("vlan")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *TrafficProtocol) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TrafficProtocol) UnmarshalBinary(b []byte) error {
	var res TrafficProtocol
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// TrafficProtocolModifiers Specifies how to modify fields of the template
//
// swagger:model TrafficProtocolModifiers
type TrafficProtocolModifiers struct {

	// List of traffic protocol modifiers
	// Required: true
	// Min Items: 1
	Items []*TrafficProtocolModifier `json:"items"`

	// Specifies how modifier tuples are generated when multiple
	// modifiers are listed.
	//
	// Enum: [cartesian zip]
	Tie *string `json:"tie,omitempty"`
}

// Validate validates this traffic protocol modifiers
func (m *TrafficProtocolModifiers) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateItems(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTie(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TrafficProtocolModifiers) validateItems(formats strfmt.Registry) error {

	if err := validate.Required("modifiers"+"."+"items", "body", m.Items); err != nil {
		return err
	}

	iItemsSize := int64(len(m.Items))

	if err := validate.MinItems("modifiers"+"."+"items", "body", iItemsSize, 1); err != nil {
		return err
	}

	for i := 0; i < len(m.Items); i++ {
		if swag.IsZero(m.Items[i]) { // not required
			continue
		}

		if m.Items[i] != nil {
			if err := m.Items[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("modifiers" + "." + "items" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

var trafficProtocolModifiersTypeTiePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["cartesian","zip"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		trafficProtocolModifiersTypeTiePropEnum = append(trafficProtocolModifiersTypeTiePropEnum, v)
	}
}

const (

	// TrafficProtocolModifiersTieCartesian captures enum value "cartesian"
	TrafficProtocolModifiersTieCartesian string = "cartesian"

	// TrafficProtocolModifiersTieZip captures enum value "zip"
	TrafficProtocolModifiersTieZip string = "zip"
)

// prop value enum
func (m *TrafficProtocolModifiers) validateTieEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, trafficProtocolModifiersTypeTiePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *TrafficProtocolModifiers) validateTie(formats strfmt.Registry) error {
	if swag.IsZero(m.Tie) { // not required
		return nil
	}

	// value enum
	if err := m.validateTieEnum("modifiers"+"."+"tie", "body", *m.Tie); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this traffic protocol modifiers based on the context it is used
func (m *TrafficProtocolModifiers) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateItems(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TrafficProtocolModifiers) contextValidateItems(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Items); i++ {

		if m.Items[i] != nil {
			if err := m.Items[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("modifiers" + "." + "items" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *TrafficProtocolModifiers) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TrafficProtocolModifiers) UnmarshalBinary(b []byte) error {
	var res TrafficProtocolModifiers
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}