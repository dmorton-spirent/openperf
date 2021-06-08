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

// NewListMemoryGeneratorResultsParams creates a new ListMemoryGeneratorResultsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListMemoryGeneratorResultsParams() *ListMemoryGeneratorResultsParams {
	return &ListMemoryGeneratorResultsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListMemoryGeneratorResultsParamsWithTimeout creates a new ListMemoryGeneratorResultsParams object
// with the ability to set a timeout on a request.
func NewListMemoryGeneratorResultsParamsWithTimeout(timeout time.Duration) *ListMemoryGeneratorResultsParams {
	return &ListMemoryGeneratorResultsParams{
		timeout: timeout,
	}
}

// NewListMemoryGeneratorResultsParamsWithContext creates a new ListMemoryGeneratorResultsParams object
// with the ability to set a context for a request.
func NewListMemoryGeneratorResultsParamsWithContext(ctx context.Context) *ListMemoryGeneratorResultsParams {
	return &ListMemoryGeneratorResultsParams{
		Context: ctx,
	}
}

// NewListMemoryGeneratorResultsParamsWithHTTPClient creates a new ListMemoryGeneratorResultsParams object
// with the ability to set a custom HTTPClient for a request.
func NewListMemoryGeneratorResultsParamsWithHTTPClient(client *http.Client) *ListMemoryGeneratorResultsParams {
	return &ListMemoryGeneratorResultsParams{
		HTTPClient: client,
	}
}

/* ListMemoryGeneratorResultsParams contains all the parameters to send to the API endpoint
   for the list memory generator results operation.

   Typically these are written to a http.Request.
*/
type ListMemoryGeneratorResultsParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the list memory generator results params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListMemoryGeneratorResultsParams) WithDefaults() *ListMemoryGeneratorResultsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list memory generator results params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListMemoryGeneratorResultsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the list memory generator results params
func (o *ListMemoryGeneratorResultsParams) WithTimeout(timeout time.Duration) *ListMemoryGeneratorResultsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list memory generator results params
func (o *ListMemoryGeneratorResultsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list memory generator results params
func (o *ListMemoryGeneratorResultsParams) WithContext(ctx context.Context) *ListMemoryGeneratorResultsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list memory generator results params
func (o *ListMemoryGeneratorResultsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list memory generator results params
func (o *ListMemoryGeneratorResultsParams) WithHTTPClient(client *http.Client) *ListMemoryGeneratorResultsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list memory generator results params
func (o *ListMemoryGeneratorResultsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *ListMemoryGeneratorResultsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}