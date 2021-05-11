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

// NewBulkCreateNetworkServersParams creates a new BulkCreateNetworkServersParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewBulkCreateNetworkServersParams() *BulkCreateNetworkServersParams {
	return &BulkCreateNetworkServersParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewBulkCreateNetworkServersParamsWithTimeout creates a new BulkCreateNetworkServersParams object
// with the ability to set a timeout on a request.
func NewBulkCreateNetworkServersParamsWithTimeout(timeout time.Duration) *BulkCreateNetworkServersParams {
	return &BulkCreateNetworkServersParams{
		timeout: timeout,
	}
}

// NewBulkCreateNetworkServersParamsWithContext creates a new BulkCreateNetworkServersParams object
// with the ability to set a context for a request.
func NewBulkCreateNetworkServersParamsWithContext(ctx context.Context) *BulkCreateNetworkServersParams {
	return &BulkCreateNetworkServersParams{
		Context: ctx,
	}
}

// NewBulkCreateNetworkServersParamsWithHTTPClient creates a new BulkCreateNetworkServersParams object
// with the ability to set a custom HTTPClient for a request.
func NewBulkCreateNetworkServersParamsWithHTTPClient(client *http.Client) *BulkCreateNetworkServersParams {
	return &BulkCreateNetworkServersParams{
		HTTPClient: client,
	}
}

/* BulkCreateNetworkServersParams contains all the parameters to send to the API endpoint
   for the bulk create network servers operation.

   Typically these are written to a http.Request.
*/
type BulkCreateNetworkServersParams struct {

	/* Create.

	   Bulk creation
	*/
	Create BulkCreateNetworkServersBody

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the bulk create network servers params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *BulkCreateNetworkServersParams) WithDefaults() *BulkCreateNetworkServersParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the bulk create network servers params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *BulkCreateNetworkServersParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the bulk create network servers params
func (o *BulkCreateNetworkServersParams) WithTimeout(timeout time.Duration) *BulkCreateNetworkServersParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the bulk create network servers params
func (o *BulkCreateNetworkServersParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the bulk create network servers params
func (o *BulkCreateNetworkServersParams) WithContext(ctx context.Context) *BulkCreateNetworkServersParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the bulk create network servers params
func (o *BulkCreateNetworkServersParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the bulk create network servers params
func (o *BulkCreateNetworkServersParams) WithHTTPClient(client *http.Client) *BulkCreateNetworkServersParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the bulk create network servers params
func (o *BulkCreateNetworkServersParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCreate adds the create to the bulk create network servers params
func (o *BulkCreateNetworkServersParams) WithCreate(create BulkCreateNetworkServersBody) *BulkCreateNetworkServersParams {
	o.SetCreate(create)
	return o
}

// SetCreate adds the create to the bulk create network servers params
func (o *BulkCreateNetworkServersParams) SetCreate(create BulkCreateNetworkServersBody) {
	o.Create = create
}

// WriteToRequest writes these params to a swagger request
func (o *BulkCreateNetworkServersParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if err := r.SetBodyParam(o.Create); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
