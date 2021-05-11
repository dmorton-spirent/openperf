// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// PacketAnalyzerFlowDigests Result digests for flows
//
// swagger:model PacketAnalyzerFlowDigests
type PacketAnalyzerFlowDigests struct {

	// frame length
	FrameLength *PacketAnalyzerFlowDigestResult `json:"frame_length,omitempty"`

	// interarrival
	Interarrival *PacketAnalyzerFlowDigestResult `json:"interarrival,omitempty"`

	// jitter ipdv
	JitterIpdv *PacketAnalyzerFlowDigestResult `json:"jitter_ipdv,omitempty"`

	// jitter rfc
	JitterRfc *PacketAnalyzerFlowDigestResult `json:"jitter_rfc,omitempty"`

	// latency
	Latency *PacketAnalyzerFlowDigestResult `json:"latency,omitempty"`

	// sequence run length
	SequenceRunLength *PacketAnalyzerFlowDigestResult `json:"sequence_run_length,omitempty"`
}

// Validate validates this packet analyzer flow digests
func (m *PacketAnalyzerFlowDigests) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateFrameLength(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInterarrival(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateJitterIpdv(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateJitterRfc(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLatency(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSequenceRunLength(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PacketAnalyzerFlowDigests) validateFrameLength(formats strfmt.Registry) error {
	if swag.IsZero(m.FrameLength) { // not required
		return nil
	}

	if m.FrameLength != nil {
		if err := m.FrameLength.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("frame_length")
			}
			return err
		}
	}

	return nil
}

func (m *PacketAnalyzerFlowDigests) validateInterarrival(formats strfmt.Registry) error {
	if swag.IsZero(m.Interarrival) { // not required
		return nil
	}

	if m.Interarrival != nil {
		if err := m.Interarrival.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("interarrival")
			}
			return err
		}
	}

	return nil
}

func (m *PacketAnalyzerFlowDigests) validateJitterIpdv(formats strfmt.Registry) error {
	if swag.IsZero(m.JitterIpdv) { // not required
		return nil
	}

	if m.JitterIpdv != nil {
		if err := m.JitterIpdv.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("jitter_ipdv")
			}
			return err
		}
	}

	return nil
}

func (m *PacketAnalyzerFlowDigests) validateJitterRfc(formats strfmt.Registry) error {
	if swag.IsZero(m.JitterRfc) { // not required
		return nil
	}

	if m.JitterRfc != nil {
		if err := m.JitterRfc.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("jitter_rfc")
			}
			return err
		}
	}

	return nil
}

func (m *PacketAnalyzerFlowDigests) validateLatency(formats strfmt.Registry) error {
	if swag.IsZero(m.Latency) { // not required
		return nil
	}

	if m.Latency != nil {
		if err := m.Latency.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("latency")
			}
			return err
		}
	}

	return nil
}

func (m *PacketAnalyzerFlowDigests) validateSequenceRunLength(formats strfmt.Registry) error {
	if swag.IsZero(m.SequenceRunLength) { // not required
		return nil
	}

	if m.SequenceRunLength != nil {
		if err := m.SequenceRunLength.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("sequence_run_length")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this packet analyzer flow digests based on the context it is used
func (m *PacketAnalyzerFlowDigests) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateFrameLength(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateInterarrival(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateJitterIpdv(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateJitterRfc(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateLatency(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSequenceRunLength(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PacketAnalyzerFlowDigests) contextValidateFrameLength(ctx context.Context, formats strfmt.Registry) error {

	if m.FrameLength != nil {
		if err := m.FrameLength.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("frame_length")
			}
			return err
		}
	}

	return nil
}

func (m *PacketAnalyzerFlowDigests) contextValidateInterarrival(ctx context.Context, formats strfmt.Registry) error {

	if m.Interarrival != nil {
		if err := m.Interarrival.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("interarrival")
			}
			return err
		}
	}

	return nil
}

func (m *PacketAnalyzerFlowDigests) contextValidateJitterIpdv(ctx context.Context, formats strfmt.Registry) error {

	if m.JitterIpdv != nil {
		if err := m.JitterIpdv.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("jitter_ipdv")
			}
			return err
		}
	}

	return nil
}

func (m *PacketAnalyzerFlowDigests) contextValidateJitterRfc(ctx context.Context, formats strfmt.Registry) error {

	if m.JitterRfc != nil {
		if err := m.JitterRfc.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("jitter_rfc")
			}
			return err
		}
	}

	return nil
}

func (m *PacketAnalyzerFlowDigests) contextValidateLatency(ctx context.Context, formats strfmt.Registry) error {

	if m.Latency != nil {
		if err := m.Latency.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("latency")
			}
			return err
		}
	}

	return nil
}

func (m *PacketAnalyzerFlowDigests) contextValidateSequenceRunLength(ctx context.Context, formats strfmt.Registry) error {

	if m.SequenceRunLength != nil {
		if err := m.SequenceRunLength.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("sequence_run_length")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *PacketAnalyzerFlowDigests) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PacketAnalyzerFlowDigests) UnmarshalBinary(b []byte) error {
	var res PacketAnalyzerFlowDigests
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
