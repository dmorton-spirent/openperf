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

// BlockFile Block file
//
// swagger:model BlockFile
type BlockFile struct {

	// Unique file identifier
	// Required: true
	ID *string `json:"id"`

	// Percentage of initialization completed so far
	// Required: true
	InitPercentComplete *int32 `json:"init_percent_complete"`

	// Resource pathname
	// Required: true
	Path *string `json:"path"`

	// Size of test file (in bytes)
	// Required: true
	// Minimum: 64
	Size *int64 `json:"size"`

	// State of resource
	// Required: true
	// Enum: [none init ready]
	State *string `json:"state"`
}

// Validate validates this block file
func (m *BlockFile) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInitPercentComplete(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePath(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSize(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateState(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *BlockFile) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *BlockFile) validateInitPercentComplete(formats strfmt.Registry) error {

	if err := validate.Required("init_percent_complete", "body", m.InitPercentComplete); err != nil {
		return err
	}

	return nil
}

func (m *BlockFile) validatePath(formats strfmt.Registry) error {

	if err := validate.Required("path", "body", m.Path); err != nil {
		return err
	}

	return nil
}

func (m *BlockFile) validateSize(formats strfmt.Registry) error {

	if err := validate.Required("size", "body", m.Size); err != nil {
		return err
	}

	if err := validate.MinimumInt("size", "body", *m.Size, 64, false); err != nil {
		return err
	}

	return nil
}

var blockFileTypeStatePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["none","init","ready"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		blockFileTypeStatePropEnum = append(blockFileTypeStatePropEnum, v)
	}
}

const (

	// BlockFileStateNone captures enum value "none"
	BlockFileStateNone string = "none"

	// BlockFileStateInit captures enum value "init"
	BlockFileStateInit string = "init"

	// BlockFileStateReady captures enum value "ready"
	BlockFileStateReady string = "ready"
)

// prop value enum
func (m *BlockFile) validateStateEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, blockFileTypeStatePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *BlockFile) validateState(formats strfmt.Registry) error {

	if err := validate.Required("state", "body", m.State); err != nil {
		return err
	}

	// value enum
	if err := m.validateStateEnum("state", "body", *m.State); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this block file based on context it is used
func (m *BlockFile) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *BlockFile) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *BlockFile) UnmarshalBinary(b []byte) error {
	var res BlockFile
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
