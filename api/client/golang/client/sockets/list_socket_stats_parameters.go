// Code generated by go-swagger; DO NOT EDIT.

package sockets

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

// NewListSocketStatsParams creates a new ListSocketStatsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListSocketStatsParams() *ListSocketStatsParams {
	return &ListSocketStatsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListSocketStatsParamsWithTimeout creates a new ListSocketStatsParams object
// with the ability to set a timeout on a request.
func NewListSocketStatsParamsWithTimeout(timeout time.Duration) *ListSocketStatsParams {
	return &ListSocketStatsParams{
		timeout: timeout,
	}
}

// NewListSocketStatsParamsWithContext creates a new ListSocketStatsParams object
// with the ability to set a context for a request.
func NewListSocketStatsParamsWithContext(ctx context.Context) *ListSocketStatsParams {
	return &ListSocketStatsParams{
		Context: ctx,
	}
}

// NewListSocketStatsParamsWithHTTPClient creates a new ListSocketStatsParams object
// with the ability to set a custom HTTPClient for a request.
func NewListSocketStatsParamsWithHTTPClient(client *http.Client) *ListSocketStatsParams {
	return &ListSocketStatsParams{
		HTTPClient: client,
	}
}

/* ListSocketStatsParams contains all the parameters to send to the API endpoint
   for the list socket stats operation.

   Typically these are written to a http.Request.
*/
type ListSocketStatsParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the list socket stats params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListSocketStatsParams) WithDefaults() *ListSocketStatsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list socket stats params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListSocketStatsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the list socket stats params
func (o *ListSocketStatsParams) WithTimeout(timeout time.Duration) *ListSocketStatsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list socket stats params
func (o *ListSocketStatsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list socket stats params
func (o *ListSocketStatsParams) WithContext(ctx context.Context) *ListSocketStatsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list socket stats params
func (o *ListSocketStatsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list socket stats params
func (o *ListSocketStatsParams) WithHTTPClient(client *http.Client) *ListSocketStatsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list socket stats params
func (o *ListSocketStatsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *ListSocketStatsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
