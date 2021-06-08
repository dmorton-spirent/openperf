// Code generated by go-swagger; DO NOT EDIT.

package packet_generators

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

// NewGetTxFlowParams creates a new GetTxFlowParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetTxFlowParams() *GetTxFlowParams {
	return &GetTxFlowParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetTxFlowParamsWithTimeout creates a new GetTxFlowParams object
// with the ability to set a timeout on a request.
func NewGetTxFlowParamsWithTimeout(timeout time.Duration) *GetTxFlowParams {
	return &GetTxFlowParams{
		timeout: timeout,
	}
}

// NewGetTxFlowParamsWithContext creates a new GetTxFlowParams object
// with the ability to set a context for a request.
func NewGetTxFlowParamsWithContext(ctx context.Context) *GetTxFlowParams {
	return &GetTxFlowParams{
		Context: ctx,
	}
}

// NewGetTxFlowParamsWithHTTPClient creates a new GetTxFlowParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetTxFlowParamsWithHTTPClient(client *http.Client) *GetTxFlowParams {
	return &GetTxFlowParams{
		HTTPClient: client,
	}
}

/* GetTxFlowParams contains all the parameters to send to the API endpoint
   for the get tx flow operation.

   Typically these are written to a http.Request.
*/
type GetTxFlowParams struct {

	/* ID.

	   Unique resource identifier

	   Format: string
	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get tx flow params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetTxFlowParams) WithDefaults() *GetTxFlowParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get tx flow params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetTxFlowParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get tx flow params
func (o *GetTxFlowParams) WithTimeout(timeout time.Duration) *GetTxFlowParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get tx flow params
func (o *GetTxFlowParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get tx flow params
func (o *GetTxFlowParams) WithContext(ctx context.Context) *GetTxFlowParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get tx flow params
func (o *GetTxFlowParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get tx flow params
func (o *GetTxFlowParams) WithHTTPClient(client *http.Client) *GetTxFlowParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get tx flow params
func (o *GetTxFlowParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the get tx flow params
func (o *GetTxFlowParams) WithID(id string) *GetTxFlowParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the get tx flow params
func (o *GetTxFlowParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *GetTxFlowParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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