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

// NewDeleteNetworkGeneratorResultParams creates a new DeleteNetworkGeneratorResultParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDeleteNetworkGeneratorResultParams() *DeleteNetworkGeneratorResultParams {
	return &DeleteNetworkGeneratorResultParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDeleteNetworkGeneratorResultParamsWithTimeout creates a new DeleteNetworkGeneratorResultParams object
// with the ability to set a timeout on a request.
func NewDeleteNetworkGeneratorResultParamsWithTimeout(timeout time.Duration) *DeleteNetworkGeneratorResultParams {
	return &DeleteNetworkGeneratorResultParams{
		timeout: timeout,
	}
}

// NewDeleteNetworkGeneratorResultParamsWithContext creates a new DeleteNetworkGeneratorResultParams object
// with the ability to set a context for a request.
func NewDeleteNetworkGeneratorResultParamsWithContext(ctx context.Context) *DeleteNetworkGeneratorResultParams {
	return &DeleteNetworkGeneratorResultParams{
		Context: ctx,
	}
}

// NewDeleteNetworkGeneratorResultParamsWithHTTPClient creates a new DeleteNetworkGeneratorResultParams object
// with the ability to set a custom HTTPClient for a request.
func NewDeleteNetworkGeneratorResultParamsWithHTTPClient(client *http.Client) *DeleteNetworkGeneratorResultParams {
	return &DeleteNetworkGeneratorResultParams{
		HTTPClient: client,
	}
}

/* DeleteNetworkGeneratorResultParams contains all the parameters to send to the API endpoint
   for the delete network generator result operation.

   Typically these are written to a http.Request.
*/
type DeleteNetworkGeneratorResultParams struct {

	/* ID.

	   Unique resource identifier

	   Format: string
	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the delete network generator result params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteNetworkGeneratorResultParams) WithDefaults() *DeleteNetworkGeneratorResultParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the delete network generator result params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteNetworkGeneratorResultParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the delete network generator result params
func (o *DeleteNetworkGeneratorResultParams) WithTimeout(timeout time.Duration) *DeleteNetworkGeneratorResultParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete network generator result params
func (o *DeleteNetworkGeneratorResultParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete network generator result params
func (o *DeleteNetworkGeneratorResultParams) WithContext(ctx context.Context) *DeleteNetworkGeneratorResultParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete network generator result params
func (o *DeleteNetworkGeneratorResultParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete network generator result params
func (o *DeleteNetworkGeneratorResultParams) WithHTTPClient(client *http.Client) *DeleteNetworkGeneratorResultParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete network generator result params
func (o *DeleteNetworkGeneratorResultParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the delete network generator result params
func (o *DeleteNetworkGeneratorResultParams) WithID(id string) *DeleteNetworkGeneratorResultParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the delete network generator result params
func (o *DeleteNetworkGeneratorResultParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *DeleteNetworkGeneratorResultParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
