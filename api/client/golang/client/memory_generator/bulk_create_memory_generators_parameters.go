// Code generated by go-swagger; DO NOT EDIT.

package memory_generator

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

// NewBulkCreateMemoryGeneratorsParams creates a new BulkCreateMemoryGeneratorsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewBulkCreateMemoryGeneratorsParams() *BulkCreateMemoryGeneratorsParams {
	return &BulkCreateMemoryGeneratorsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewBulkCreateMemoryGeneratorsParamsWithTimeout creates a new BulkCreateMemoryGeneratorsParams object
// with the ability to set a timeout on a request.
func NewBulkCreateMemoryGeneratorsParamsWithTimeout(timeout time.Duration) *BulkCreateMemoryGeneratorsParams {
	return &BulkCreateMemoryGeneratorsParams{
		timeout: timeout,
	}
}

// NewBulkCreateMemoryGeneratorsParamsWithContext creates a new BulkCreateMemoryGeneratorsParams object
// with the ability to set a context for a request.
func NewBulkCreateMemoryGeneratorsParamsWithContext(ctx context.Context) *BulkCreateMemoryGeneratorsParams {
	return &BulkCreateMemoryGeneratorsParams{
		Context: ctx,
	}
}

// NewBulkCreateMemoryGeneratorsParamsWithHTTPClient creates a new BulkCreateMemoryGeneratorsParams object
// with the ability to set a custom HTTPClient for a request.
func NewBulkCreateMemoryGeneratorsParamsWithHTTPClient(client *http.Client) *BulkCreateMemoryGeneratorsParams {
	return &BulkCreateMemoryGeneratorsParams{
		HTTPClient: client,
	}
}

/* BulkCreateMemoryGeneratorsParams contains all the parameters to send to the API endpoint
   for the bulk create memory generators operation.

   Typically these are written to a http.Request.
*/
type BulkCreateMemoryGeneratorsParams struct {

	/* Create.

	   Bulk creation
	*/
	Create BulkCreateMemoryGeneratorsBody

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the bulk create memory generators params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *BulkCreateMemoryGeneratorsParams) WithDefaults() *BulkCreateMemoryGeneratorsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the bulk create memory generators params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *BulkCreateMemoryGeneratorsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the bulk create memory generators params
func (o *BulkCreateMemoryGeneratorsParams) WithTimeout(timeout time.Duration) *BulkCreateMemoryGeneratorsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the bulk create memory generators params
func (o *BulkCreateMemoryGeneratorsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the bulk create memory generators params
func (o *BulkCreateMemoryGeneratorsParams) WithContext(ctx context.Context) *BulkCreateMemoryGeneratorsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the bulk create memory generators params
func (o *BulkCreateMemoryGeneratorsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the bulk create memory generators params
func (o *BulkCreateMemoryGeneratorsParams) WithHTTPClient(client *http.Client) *BulkCreateMemoryGeneratorsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the bulk create memory generators params
func (o *BulkCreateMemoryGeneratorsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCreate adds the create to the bulk create memory generators params
func (o *BulkCreateMemoryGeneratorsParams) WithCreate(create BulkCreateMemoryGeneratorsBody) *BulkCreateMemoryGeneratorsParams {
	o.SetCreate(create)
	return o
}

// SetCreate adds the create to the bulk create memory generators params
func (o *BulkCreateMemoryGeneratorsParams) SetCreate(create BulkCreateMemoryGeneratorsBody) {
	o.Create = create
}

// WriteToRequest writes these params to a swagger request
func (o *BulkCreateMemoryGeneratorsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
