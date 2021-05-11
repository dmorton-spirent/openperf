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

	"github.com/spirent/openperf/api/client/golang/models"
)

// NewCreateMemoryGeneratorParams creates a new CreateMemoryGeneratorParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateMemoryGeneratorParams() *CreateMemoryGeneratorParams {
	return &CreateMemoryGeneratorParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateMemoryGeneratorParamsWithTimeout creates a new CreateMemoryGeneratorParams object
// with the ability to set a timeout on a request.
func NewCreateMemoryGeneratorParamsWithTimeout(timeout time.Duration) *CreateMemoryGeneratorParams {
	return &CreateMemoryGeneratorParams{
		timeout: timeout,
	}
}

// NewCreateMemoryGeneratorParamsWithContext creates a new CreateMemoryGeneratorParams object
// with the ability to set a context for a request.
func NewCreateMemoryGeneratorParamsWithContext(ctx context.Context) *CreateMemoryGeneratorParams {
	return &CreateMemoryGeneratorParams{
		Context: ctx,
	}
}

// NewCreateMemoryGeneratorParamsWithHTTPClient creates a new CreateMemoryGeneratorParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateMemoryGeneratorParamsWithHTTPClient(client *http.Client) *CreateMemoryGeneratorParams {
	return &CreateMemoryGeneratorParams{
		HTTPClient: client,
	}
}

/* CreateMemoryGeneratorParams contains all the parameters to send to the API endpoint
   for the create memory generator operation.

   Typically these are written to a http.Request.
*/
type CreateMemoryGeneratorParams struct {

	/* Generator.

	   New memory generator
	*/
	Generator *models.MemoryGenerator

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create memory generator params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateMemoryGeneratorParams) WithDefaults() *CreateMemoryGeneratorParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create memory generator params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateMemoryGeneratorParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the create memory generator params
func (o *CreateMemoryGeneratorParams) WithTimeout(timeout time.Duration) *CreateMemoryGeneratorParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create memory generator params
func (o *CreateMemoryGeneratorParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create memory generator params
func (o *CreateMemoryGeneratorParams) WithContext(ctx context.Context) *CreateMemoryGeneratorParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create memory generator params
func (o *CreateMemoryGeneratorParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create memory generator params
func (o *CreateMemoryGeneratorParams) WithHTTPClient(client *http.Client) *CreateMemoryGeneratorParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create memory generator params
func (o *CreateMemoryGeneratorParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithGenerator adds the generator to the create memory generator params
func (o *CreateMemoryGeneratorParams) WithGenerator(generator *models.MemoryGenerator) *CreateMemoryGeneratorParams {
	o.SetGenerator(generator)
	return o
}

// SetGenerator adds the generator to the create memory generator params
func (o *CreateMemoryGeneratorParams) SetGenerator(generator *models.MemoryGenerator) {
	o.Generator = generator
}

// WriteToRequest writes these params to a swagger request
func (o *CreateMemoryGeneratorParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Generator != nil {
		if err := r.SetBodyParam(o.Generator); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
