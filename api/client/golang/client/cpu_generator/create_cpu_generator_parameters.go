// Code generated by go-swagger; DO NOT EDIT.

package cpu_generator

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

// NewCreateCPUGeneratorParams creates a new CreateCPUGeneratorParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateCPUGeneratorParams() *CreateCPUGeneratorParams {
	return &CreateCPUGeneratorParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateCPUGeneratorParamsWithTimeout creates a new CreateCPUGeneratorParams object
// with the ability to set a timeout on a request.
func NewCreateCPUGeneratorParamsWithTimeout(timeout time.Duration) *CreateCPUGeneratorParams {
	return &CreateCPUGeneratorParams{
		timeout: timeout,
	}
}

// NewCreateCPUGeneratorParamsWithContext creates a new CreateCPUGeneratorParams object
// with the ability to set a context for a request.
func NewCreateCPUGeneratorParamsWithContext(ctx context.Context) *CreateCPUGeneratorParams {
	return &CreateCPUGeneratorParams{
		Context: ctx,
	}
}

// NewCreateCPUGeneratorParamsWithHTTPClient creates a new CreateCPUGeneratorParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateCPUGeneratorParamsWithHTTPClient(client *http.Client) *CreateCPUGeneratorParams {
	return &CreateCPUGeneratorParams{
		HTTPClient: client,
	}
}

/* CreateCPUGeneratorParams contains all the parameters to send to the API endpoint
   for the create Cpu generator operation.

   Typically these are written to a http.Request.
*/
type CreateCPUGeneratorParams struct {

	/* Generator.

	   New CPU generator
	*/
	Generator *models.CPUGenerator

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create Cpu generator params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateCPUGeneratorParams) WithDefaults() *CreateCPUGeneratorParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create Cpu generator params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateCPUGeneratorParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the create Cpu generator params
func (o *CreateCPUGeneratorParams) WithTimeout(timeout time.Duration) *CreateCPUGeneratorParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create Cpu generator params
func (o *CreateCPUGeneratorParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create Cpu generator params
func (o *CreateCPUGeneratorParams) WithContext(ctx context.Context) *CreateCPUGeneratorParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create Cpu generator params
func (o *CreateCPUGeneratorParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create Cpu generator params
func (o *CreateCPUGeneratorParams) WithHTTPClient(client *http.Client) *CreateCPUGeneratorParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create Cpu generator params
func (o *CreateCPUGeneratorParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithGenerator adds the generator to the create Cpu generator params
func (o *CreateCPUGeneratorParams) WithGenerator(generator *models.CPUGenerator) *CreateCPUGeneratorParams {
	o.SetGenerator(generator)
	return o
}

// SetGenerator adds the generator to the create Cpu generator params
func (o *CreateCPUGeneratorParams) SetGenerator(generator *models.CPUGenerator) {
	o.Generator = generator
}

// WriteToRequest writes these params to a swagger request
func (o *CreateCPUGeneratorParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
