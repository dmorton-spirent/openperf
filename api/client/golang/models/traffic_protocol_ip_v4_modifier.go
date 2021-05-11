// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// TrafficProtocolIPV4Modifier Specifies how to modify an IPv4 address
//
// swagger:model trafficProtocolIpv4Modifier
type TrafficProtocolIPV4Modifier struct {

	// List of IPv4 addresses
	// Min Items: 1
	List []string `json:"list"`

	// sequence
	Sequence *TrafficProtocolIPV4ModifierSequence `json:"sequence,omitempty"`
}

// Validate validates this traffic protocol Ipv4 modifier
func (m *TrafficProtocolIPV4Modifier) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateList(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSequence(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TrafficProtocolIPV4Modifier) validateList(formats strfmt.Registry) error {
	if swag.IsZero(m.List) { // not required
		return nil
	}

	iListSize := int64(len(m.List))

	if err := validate.MinItems("list", "body", iListSize, 1); err != nil {
		return err
	}

	for i := 0; i < len(m.List); i++ {

		if err := validate.Pattern("list"+"."+strconv.Itoa(i), "body", m.List[i], `^((25[0-5]|2[0-4][0-9]|[01]?[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[1-9]?[0-9])$`); err != nil {
			return err
		}

	}

	return nil
}

func (m *TrafficProtocolIPV4Modifier) validateSequence(formats strfmt.Registry) error {
	if swag.IsZero(m.Sequence) { // not required
		return nil
	}

	if m.Sequence != nil {
		if err := m.Sequence.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("sequence")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this traffic protocol Ipv4 modifier based on the context it is used
func (m *TrafficProtocolIPV4Modifier) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateSequence(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TrafficProtocolIPV4Modifier) contextValidateSequence(ctx context.Context, formats strfmt.Registry) error {

	if m.Sequence != nil {
		if err := m.Sequence.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("sequence")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *TrafficProtocolIPV4Modifier) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TrafficProtocolIPV4Modifier) UnmarshalBinary(b []byte) error {
	var res TrafficProtocolIPV4Modifier
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// TrafficProtocolIPV4ModifierSequence Specifies a sequence of IPv4 addresses
//
// swagger:model TrafficProtocolIPV4ModifierSequence
type TrafficProtocolIPV4ModifierSequence struct {

	// The number of addresses in the sequence
	// Required: true
	// Minimum: 1
	Count *int32 `json:"count"`

	// List of addresses in the sequence to skip
	Skip []string `json:"skip"`

	// First IPv4 address in the sequence
	// Required: true
	// Pattern: ^((25[0-5]|2[0-4][0-9]|[01]?[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[1-9]?[0-9])$
	Start *string `json:"start"`

	// Last IPv4 address in the sequence
	// Pattern: ^((25[0-5]|2[0-4][0-9]|[01]?[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[1-9]?[0-9])$
	Stop string `json:"stop,omitempty"`
}

// Validate validates this traffic protocol IP v4 modifier sequence
func (m *TrafficProtocolIPV4ModifierSequence) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSkip(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStart(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStop(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TrafficProtocolIPV4ModifierSequence) validateCount(formats strfmt.Registry) error {

	if err := validate.Required("sequence"+"."+"count", "body", m.Count); err != nil {
		return err
	}

	if err := validate.MinimumInt("sequence"+"."+"count", "body", int64(*m.Count), 1, false); err != nil {
		return err
	}

	return nil
}

func (m *TrafficProtocolIPV4ModifierSequence) validateSkip(formats strfmt.Registry) error {
	if swag.IsZero(m.Skip) { // not required
		return nil
	}

	for i := 0; i < len(m.Skip); i++ {

		if err := validate.Pattern("sequence"+"."+"skip"+"."+strconv.Itoa(i), "body", m.Skip[i], `^((25[0-5]|2[0-4][0-9]|[01]?[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[1-9]?[0-9])$`); err != nil {
			return err
		}

	}

	return nil
}

func (m *TrafficProtocolIPV4ModifierSequence) validateStart(formats strfmt.Registry) error {

	if err := validate.Required("sequence"+"."+"start", "body", m.Start); err != nil {
		return err
	}

	if err := validate.Pattern("sequence"+"."+"start", "body", *m.Start, `^((25[0-5]|2[0-4][0-9]|[01]?[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[1-9]?[0-9])$`); err != nil {
		return err
	}

	return nil
}

func (m *TrafficProtocolIPV4ModifierSequence) validateStop(formats strfmt.Registry) error {
	if swag.IsZero(m.Stop) { // not required
		return nil
	}

	if err := validate.Pattern("sequence"+"."+"stop", "body", m.Stop, `^((25[0-5]|2[0-4][0-9]|[01]?[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[1-9]?[0-9])$`); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this traffic protocol IP v4 modifier sequence based on context it is used
func (m *TrafficProtocolIPV4ModifierSequence) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *TrafficProtocolIPV4ModifierSequence) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TrafficProtocolIPV4ModifierSequence) UnmarshalBinary(b []byte) error {
	var res TrafficProtocolIPV4ModifierSequence
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
