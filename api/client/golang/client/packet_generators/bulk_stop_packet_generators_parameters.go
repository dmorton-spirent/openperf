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

// NewBulkStopPacketGeneratorsParams creates a new BulkStopPacketGeneratorsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewBulkStopPacketGeneratorsParams() *BulkStopPacketGeneratorsParams {
	return &BulkStopPacketGeneratorsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewBulkStopPacketGeneratorsParamsWithTimeout creates a new BulkStopPacketGeneratorsParams object
// with the ability to set a timeout on a request.
func NewBulkStopPacketGeneratorsParamsWithTimeout(timeout time.Duration) *BulkStopPacketGeneratorsParams {
	return &BulkStopPacketGeneratorsParams{
		timeout: timeout,
	}
}

// NewBulkStopPacketGeneratorsParamsWithContext creates a new BulkStopPacketGeneratorsParams object
// with the ability to set a context for a request.
func NewBulkStopPacketGeneratorsParamsWithContext(ctx context.Context) *BulkStopPacketGeneratorsParams {
	return &BulkStopPacketGeneratorsParams{
		Context: ctx,
	}
}

// NewBulkStopPacketGeneratorsParamsWithHTTPClient creates a new BulkStopPacketGeneratorsParams object
// with the ability to set a custom HTTPClient for a request.
func NewBulkStopPacketGeneratorsParamsWithHTTPClient(client *http.Client) *BulkStopPacketGeneratorsParams {
	return &BulkStopPacketGeneratorsParams{
		HTTPClient: client,
	}
}

/* BulkStopPacketGeneratorsParams contains all the parameters to send to the API endpoint
   for the bulk stop packet generators operation.

   Typically these are written to a http.Request.
*/
type BulkStopPacketGeneratorsParams struct {

	/* Stop.

	   Bulk stop
	*/
	Stop BulkStopPacketGeneratorsBody

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the bulk stop packet generators params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *BulkStopPacketGeneratorsParams) WithDefaults() *BulkStopPacketGeneratorsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the bulk stop packet generators params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *BulkStopPacketGeneratorsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the bulk stop packet generators params
func (o *BulkStopPacketGeneratorsParams) WithTimeout(timeout time.Duration) *BulkStopPacketGeneratorsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the bulk stop packet generators params
func (o *BulkStopPacketGeneratorsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the bulk stop packet generators params
func (o *BulkStopPacketGeneratorsParams) WithContext(ctx context.Context) *BulkStopPacketGeneratorsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the bulk stop packet generators params
func (o *BulkStopPacketGeneratorsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the bulk stop packet generators params
func (o *BulkStopPacketGeneratorsParams) WithHTTPClient(client *http.Client) *BulkStopPacketGeneratorsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the bulk stop packet generators params
func (o *BulkStopPacketGeneratorsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithStop adds the stop to the bulk stop packet generators params
func (o *BulkStopPacketGeneratorsParams) WithStop(stop BulkStopPacketGeneratorsBody) *BulkStopPacketGeneratorsParams {
	o.SetStop(stop)
	return o
}

// SetStop adds the stop to the bulk stop packet generators params
func (o *BulkStopPacketGeneratorsParams) SetStop(stop BulkStopPacketGeneratorsBody) {
	o.Stop = stop
}

// WriteToRequest writes these params to a swagger request
func (o *BulkStopPacketGeneratorsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if err := r.SetBodyParam(o.Stop); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
