// Code generated by go-swagger; DO NOT EDIT.

package t_v_l_p

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

// NewGetTvlpResultParams creates a new GetTvlpResultParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetTvlpResultParams() *GetTvlpResultParams {
	return &GetTvlpResultParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetTvlpResultParamsWithTimeout creates a new GetTvlpResultParams object
// with the ability to set a timeout on a request.
func NewGetTvlpResultParamsWithTimeout(timeout time.Duration) *GetTvlpResultParams {
	return &GetTvlpResultParams{
		timeout: timeout,
	}
}

// NewGetTvlpResultParamsWithContext creates a new GetTvlpResultParams object
// with the ability to set a context for a request.
func NewGetTvlpResultParamsWithContext(ctx context.Context) *GetTvlpResultParams {
	return &GetTvlpResultParams{
		Context: ctx,
	}
}

// NewGetTvlpResultParamsWithHTTPClient creates a new GetTvlpResultParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetTvlpResultParamsWithHTTPClient(client *http.Client) *GetTvlpResultParams {
	return &GetTvlpResultParams{
		HTTPClient: client,
	}
}

/* GetTvlpResultParams contains all the parameters to send to the API endpoint
   for the get tvlp result operation.

   Typically these are written to a http.Request.
*/
type GetTvlpResultParams struct {

	/* ID.

	   Unique resource identifier

	   Format: string
	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get tvlp result params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetTvlpResultParams) WithDefaults() *GetTvlpResultParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get tvlp result params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetTvlpResultParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get tvlp result params
func (o *GetTvlpResultParams) WithTimeout(timeout time.Duration) *GetTvlpResultParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get tvlp result params
func (o *GetTvlpResultParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get tvlp result params
func (o *GetTvlpResultParams) WithContext(ctx context.Context) *GetTvlpResultParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get tvlp result params
func (o *GetTvlpResultParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get tvlp result params
func (o *GetTvlpResultParams) WithHTTPClient(client *http.Client) *GetTvlpResultParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get tvlp result params
func (o *GetTvlpResultParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the get tvlp result params
func (o *GetTvlpResultParams) WithID(id string) *GetTvlpResultParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the get tvlp result params
func (o *GetTvlpResultParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *GetTvlpResultParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
