// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// NetworkGeneratorConfig Network generator configuration
//
// swagger:model NetworkGeneratorConfig
type NetworkGeneratorConfig struct {

	// Number of connections to establish with the server
	// Required: true
	// Minimum: 1
	Connections *int64 `json:"connections"`

	// Number of operations over a connection before closed
	// Required: true
	// Minimum: 1
	OpsPerConnection *int64 `json:"ops_per_connection"`

	// ratio
	Ratio *NetworkGeneratorConfigRatio `json:"ratio,omitempty"`

	// Number of bytes to request from the server per read operation
	// Required: true
	// Minimum: 0
	ReadSize *int64 `json:"read_size"`

	// Number of read opertions to perform per second
	// Required: true
	// Minimum: 0
	ReadsPerSec *int64 `json:"reads_per_sec"`

	// target
	Target *NetworkGeneratorConfigTarget `json:"target,omitempty"`

	// Number of bytes to send to the server per write operation
	// Required: true
	// Minimum: 0
	WriteSize *int64 `json:"write_size"`

	// Number of write operations to perform per second
	// Required: true
	// Minimum: 0
	WritesPerSec *int64 `json:"writes_per_sec"`
}

// Validate validates this network generator config
func (m *NetworkGeneratorConfig) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateConnections(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOpsPerConnection(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRatio(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateReadSize(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateReadsPerSec(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTarget(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateWriteSize(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateWritesPerSec(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *NetworkGeneratorConfig) validateConnections(formats strfmt.Registry) error {

	if err := validate.Required("connections", "body", m.Connections); err != nil {
		return err
	}

	if err := validate.MinimumInt("connections", "body", *m.Connections, 1, false); err != nil {
		return err
	}

	return nil
}

func (m *NetworkGeneratorConfig) validateOpsPerConnection(formats strfmt.Registry) error {

	if err := validate.Required("ops_per_connection", "body", m.OpsPerConnection); err != nil {
		return err
	}

	if err := validate.MinimumInt("ops_per_connection", "body", *m.OpsPerConnection, 1, false); err != nil {
		return err
	}

	return nil
}

func (m *NetworkGeneratorConfig) validateRatio(formats strfmt.Registry) error {
	if swag.IsZero(m.Ratio) { // not required
		return nil
	}

	if m.Ratio != nil {
		if err := m.Ratio.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ratio")
			}
			return err
		}
	}

	return nil
}

func (m *NetworkGeneratorConfig) validateReadSize(formats strfmt.Registry) error {

	if err := validate.Required("read_size", "body", m.ReadSize); err != nil {
		return err
	}

	if err := validate.MinimumInt("read_size", "body", *m.ReadSize, 0, false); err != nil {
		return err
	}

	return nil
}

func (m *NetworkGeneratorConfig) validateReadsPerSec(formats strfmt.Registry) error {

	if err := validate.Required("reads_per_sec", "body", m.ReadsPerSec); err != nil {
		return err
	}

	if err := validate.MinimumInt("reads_per_sec", "body", *m.ReadsPerSec, 0, false); err != nil {
		return err
	}

	return nil
}

func (m *NetworkGeneratorConfig) validateTarget(formats strfmt.Registry) error {
	if swag.IsZero(m.Target) { // not required
		return nil
	}

	if m.Target != nil {
		if err := m.Target.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("target")
			}
			return err
		}
	}

	return nil
}

func (m *NetworkGeneratorConfig) validateWriteSize(formats strfmt.Registry) error {

	if err := validate.Required("write_size", "body", m.WriteSize); err != nil {
		return err
	}

	if err := validate.MinimumInt("write_size", "body", *m.WriteSize, 0, false); err != nil {
		return err
	}

	return nil
}

func (m *NetworkGeneratorConfig) validateWritesPerSec(formats strfmt.Registry) error {

	if err := validate.Required("writes_per_sec", "body", m.WritesPerSec); err != nil {
		return err
	}

	if err := validate.MinimumInt("writes_per_sec", "body", *m.WritesPerSec, 0, false); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this network generator config based on the context it is used
func (m *NetworkGeneratorConfig) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateRatio(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTarget(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *NetworkGeneratorConfig) contextValidateRatio(ctx context.Context, formats strfmt.Registry) error {

	if m.Ratio != nil {
		if err := m.Ratio.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ratio")
			}
			return err
		}
	}

	return nil
}

func (m *NetworkGeneratorConfig) contextValidateTarget(ctx context.Context, formats strfmt.Registry) error {

	if m.Target != nil {
		if err := m.Target.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("target")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *NetworkGeneratorConfig) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *NetworkGeneratorConfig) UnmarshalBinary(b []byte) error {
	var res NetworkGeneratorConfig
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// NetworkGeneratorConfigRatio NetworkGeneratorReadWriteRatio
//
// Relative amount of a mixed workload operations that should be performed. If value is not given, ratio is not limited.
//
// swagger:model NetworkGeneratorConfigRatio
type NetworkGeneratorConfigRatio struct {

	// reads
	// Required: true
	// Minimum: 1
	Reads *int64 `json:"reads"`

	// writes
	// Required: true
	// Minimum: 1
	Writes *int64 `json:"writes"`
}

// Validate validates this network generator config ratio
func (m *NetworkGeneratorConfigRatio) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateReads(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateWrites(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *NetworkGeneratorConfigRatio) validateReads(formats strfmt.Registry) error {

	if err := validate.Required("ratio"+"."+"reads", "body", m.Reads); err != nil {
		return err
	}

	if err := validate.MinimumInt("ratio"+"."+"reads", "body", *m.Reads, 1, false); err != nil {
		return err
	}

	return nil
}

func (m *NetworkGeneratorConfigRatio) validateWrites(formats strfmt.Registry) error {

	if err := validate.Required("ratio"+"."+"writes", "body", m.Writes); err != nil {
		return err
	}

	if err := validate.MinimumInt("ratio"+"."+"writes", "body", *m.Writes, 1, false); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this network generator config ratio based on context it is used
func (m *NetworkGeneratorConfigRatio) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *NetworkGeneratorConfigRatio) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *NetworkGeneratorConfigRatio) UnmarshalBinary(b []byte) error {
	var res NetworkGeneratorConfigRatio
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// NetworkGeneratorConfigTarget Network generator connection configuration
//
// swagger:model NetworkGeneratorConfigTarget
type NetworkGeneratorConfigTarget struct {

	// Remote host to establish a connection
	// Required: true
	Host *string `json:"host"`

	// Bind client socket to a particular device, specified as interface name (required for dpdk driver)
	Interface string `json:"interface,omitempty"`

	// Port on which client is trying to establish connection
	// Required: true
	// Maximum: 65535
	// Minimum: 0
	Port *int64 `json:"port"`

	// Protocol to establish connection between client and host
	// Required: true
	// Enum: [tcp udp]
	Protocol *string `json:"protocol"`
}

// Validate validates this network generator config target
func (m *NetworkGeneratorConfigTarget) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateHost(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePort(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProtocol(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *NetworkGeneratorConfigTarget) validateHost(formats strfmt.Registry) error {

	if err := validate.Required("target"+"."+"host", "body", m.Host); err != nil {
		return err
	}

	return nil
}

func (m *NetworkGeneratorConfigTarget) validatePort(formats strfmt.Registry) error {

	if err := validate.Required("target"+"."+"port", "body", m.Port); err != nil {
		return err
	}

	if err := validate.MinimumInt("target"+"."+"port", "body", *m.Port, 0, false); err != nil {
		return err
	}

	if err := validate.MaximumInt("target"+"."+"port", "body", *m.Port, 65535, false); err != nil {
		return err
	}

	return nil
}

var networkGeneratorConfigTargetTypeProtocolPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["tcp","udp"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		networkGeneratorConfigTargetTypeProtocolPropEnum = append(networkGeneratorConfigTargetTypeProtocolPropEnum, v)
	}
}

const (

	// NetworkGeneratorConfigTargetProtocolTCP captures enum value "tcp"
	NetworkGeneratorConfigTargetProtocolTCP string = "tcp"

	// NetworkGeneratorConfigTargetProtocolUDP captures enum value "udp"
	NetworkGeneratorConfigTargetProtocolUDP string = "udp"
)

// prop value enum
func (m *NetworkGeneratorConfigTarget) validateProtocolEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, networkGeneratorConfigTargetTypeProtocolPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *NetworkGeneratorConfigTarget) validateProtocol(formats strfmt.Registry) error {

	if err := validate.Required("target"+"."+"protocol", "body", m.Protocol); err != nil {
		return err
	}

	// value enum
	if err := m.validateProtocolEnum("target"+"."+"protocol", "body", *m.Protocol); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this network generator config target based on context it is used
func (m *NetworkGeneratorConfigTarget) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *NetworkGeneratorConfigTarget) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *NetworkGeneratorConfigTarget) UnmarshalBinary(b []byte) error {
	var res NetworkGeneratorConfigTarget
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}