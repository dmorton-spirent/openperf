// Code generated by go-swagger; DO NOT EDIT.

package network_generator

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewStopNetworkGeneratorParams creates a new StopNetworkGeneratorParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewStopNetworkGeneratorParams() *StopNetworkGeneratorParams {
	return &StopNetworkGeneratorParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewStopNetworkGeneratorParamsWithTimeout creates a new StopNetworkGeneratorParams object
// with the ability to set a timeout on a request.
func NewStopNetworkGeneratorParamsWithTimeout(timeout time.Duration) *StopNetworkGeneratorParams {
	return &StopNetworkGeneratorParams{
		timeout: timeout,
	}
}

// NewStopNetworkGeneratorParamsWithContext creates a new StopNetworkGeneratorParams object
// with the ability to set a context for a request.
func NewStopNetworkGeneratorParamsWithContext(ctx context.Context) *StopNetworkGeneratorParams {
	return &StopNetworkGeneratorParams{
		Context: ctx,
	}
}

// NewStopNetworkGeneratorParamsWithHTTPClient creates a new StopNetworkGeneratorParams object
// with the ability to set a custom HTTPClient for a request.
func NewStopNetworkGeneratorParamsWithHTTPClient(client *http.Client) *StopNetworkGeneratorParams {
	return &StopNetworkGeneratorParams{
		HTTPClient: client,
	}
}

/* StopNetworkGeneratorParams contains all the parameters to send to the API endpoint
   for the stop network generator operation.

   Typically these are written to a http.Request.
*/
type StopNetworkGeneratorParams struct {

	/* ID.

	   Unique resource identifier

	   Format: string
	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the stop network generator params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *StopNetworkGeneratorParams) WithDefaults() *StopNetworkGeneratorParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the stop network generator params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *StopNetworkGeneratorParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the stop network generator params
func (o *StopNetworkGeneratorParams) WithTimeout(timeout time.Duration) *StopNetworkGeneratorParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the stop network generator params
func (o *StopNetworkGeneratorParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the stop network generator params
func (o *StopNetworkGeneratorParams) WithContext(ctx context.Context) *StopNetworkGeneratorParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the stop network generator params
func (o *StopNetworkGeneratorParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the stop network generator params
func (o *StopNetworkGeneratorParams) WithHTTPClient(client *http.Client) *StopNetworkGeneratorParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the stop network generator params
func (o *StopNetworkGeneratorParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the stop network generator params
func (o *StopNetworkGeneratorParams) WithID(id string) *StopNetworkGeneratorParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the stop network generator params
func (o *StopNetworkGeneratorParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *StopNetworkGeneratorParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param id
	if err := r.SetPathParam("id", o.ID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
