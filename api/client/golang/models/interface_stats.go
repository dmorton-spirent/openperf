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

// InterfaceStats Per-interface statistics
//
// swagger:model InterfaceStats
type InterfaceStats struct {

	// Received bytes
	// Required: true
	RxBytes *int64 `json:"rx_bytes"`

	// Receive-side errors
	// Required: true
	RxErrors *int64 `json:"rx_errors"`

	// Received packets
	// Required: true
	RxPackets *int64 `json:"rx_packets"`

	// Transmitted bytes
	// Required: true
	TxBytes *int64 `json:"tx_bytes"`

	// Transmit-side errors
	// Required: true
	TxErrors *int64 `json:"tx_errors"`

	// Transmitted packets
	// Required: true
	TxPackets *int64 `json:"tx_packets"`
}

// Validate validates this interface stats
func (m *InterfaceStats) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateRxBytes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRxErrors(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRxPackets(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTxBytes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTxErrors(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTxPackets(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *InterfaceStats) validateRxBytes(formats strfmt.Registry) error {

	if err := validate.Required("rx_bytes", "body", m.RxBytes); err != nil {
		return err
	}

	return nil
}

func (m *InterfaceStats) validateRxErrors(formats strfmt.Registry) error {

	if err := validate.Required("rx_errors", "body", m.RxErrors); err != nil {
		return err
	}

	return nil
}

func (m *InterfaceStats) validateRxPackets(formats strfmt.Registry) error {

	if err := validate.Required("rx_packets", "body", m.RxPackets); err != nil {
		return err
	}

	return nil
}

func (m *InterfaceStats) validateTxBytes(formats strfmt.Registry) error {

	if err := validate.Required("tx_bytes", "body", m.TxBytes); err != nil {
		return err
	}

	return nil
}

func (m *InterfaceStats) validateTxErrors(formats strfmt.Registry) error {

	if err := validate.Required("tx_errors", "body", m.TxErrors); err != nil {
		return err
	}

	return nil
}

func (m *InterfaceStats) validateTxPackets(formats strfmt.Registry) error {

	if err := validate.Required("tx_packets", "body", m.TxPackets); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this interface stats based on context it is used
func (m *InterfaceStats) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *InterfaceStats) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *InterfaceStats) UnmarshalBinary(b []byte) error {
	var res InterfaceStats
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
