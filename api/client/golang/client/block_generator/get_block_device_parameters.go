// Code generated by go-swagger; DO NOT EDIT.

package block_generator

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

// NewGetBlockDeviceParams creates a new GetBlockDeviceParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetBlockDeviceParams() *GetBlockDeviceParams {
	return &GetBlockDeviceParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetBlockDeviceParamsWithTimeout creates a new GetBlockDeviceParams object
// with the ability to set a timeout on a request.
func NewGetBlockDeviceParamsWithTimeout(timeout time.Duration) *GetBlockDeviceParams {
	return &GetBlockDeviceParams{
		timeout: timeout,
	}
}

// NewGetBlockDeviceParamsWithContext creates a new GetBlockDeviceParams object
// with the ability to set a context for a request.
func NewGetBlockDeviceParamsWithContext(ctx context.Context) *GetBlockDeviceParams {
	return &GetBlockDeviceParams{
		Context: ctx,
	}
}

// NewGetBlockDeviceParamsWithHTTPClient creates a new GetBlockDeviceParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetBlockDeviceParamsWithHTTPClient(client *http.Client) *GetBlockDeviceParams {
	return &GetBlockDeviceParams{
		HTTPClient: client,
	}
}

/* GetBlockDeviceParams contains all the parameters to send to the API endpoint
   for the get block device operation.

   Typically these are written to a http.Request.
*/
type GetBlockDeviceParams struct {

	/* ID.

	   Unique resource identifier

	   Format: string
	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get block device params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetBlockDeviceParams) WithDefaults() *GetBlockDeviceParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get block device params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetBlockDeviceParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get block device params
func (o *GetBlockDeviceParams) WithTimeout(timeout time.Duration) *GetBlockDeviceParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get block device params
func (o *GetBlockDeviceParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get block device params
func (o *GetBlockDeviceParams) WithContext(ctx context.Context) *GetBlockDeviceParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get block device params
func (o *GetBlockDeviceParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get block device params
func (o *GetBlockDeviceParams) WithHTTPClient(client *http.Client) *GetBlockDeviceParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get block device params
func (o *GetBlockDeviceParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the get block device params
func (o *GetBlockDeviceParams) WithID(id string) *GetBlockDeviceParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the get block device params
func (o *GetBlockDeviceParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *GetBlockDeviceParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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