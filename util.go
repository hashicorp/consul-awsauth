// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package iamauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/hashicorp/consul-awsauth/responses"
	"github.com/hashicorp/go-hclog"
)

type LoginInput struct {
	// Creds is the AWS credentials provider (v2 uses interface instead of pointer)
	Creds            aws.CredentialsProvider
	IncludeIAMEntity bool
	STSEndpoint      string
	IAMEndpoint      string
	STSRegion        string

	Logger hclog.Logger

	ServerIDHeaderValue string
	// Customizable header names
	ServerIDHeaderName     string
	GetEntityMethodHeader  string
	GetEntityURLHeader     string
	GetEntityHeadersHeader string
	GetEntityBodyHeader    string
}

// GenerateLoginData populates the necessary data to send for the bearer token.
func GenerateLoginData(in *LoginInput) (map[string]interface{}, error) {
	//Validates the passed input data
	if in == nil {
		return nil, fmt.Errorf("LoginInput cannot be nil")
	}
	if in.Creds == nil {
		return nil, fmt.Errorf("credentials provider is required")
	}
	if in.STSRegion == "" {
		return nil, fmt.Errorf("STS region is required")
	}
	if in.IncludeIAMEntity {
		if in.GetEntityMethodHeader == "" {
			return nil, fmt.Errorf("GetEntityMethodHeader is required when IncludeIAMEntity is true")
		}
		if in.GetEntityURLHeader == "" {
			return nil, fmt.Errorf("GetEntityURLHeader is required when IncludeIAMEntity is true")
		}
		if in.GetEntityHeadersHeader == "" {
			return nil, fmt.Errorf("GetEntityHeadersHeader is required when IncludeIAMEntity is true")
		}
		if in.GetEntityBodyHeader == "" {
			return nil, fmt.Errorf("GetEntityBodyHeader is required when IncludeIAMEntity is true")
		}
	}

	ctx := context.Background()

	// Build AWS config from credentials provider
	// Following v2 pattern: direct struct initialization with required fields
	cfg := aws.Config{
		Credentials: in.Creds,
		Region:      in.STSRegion,
	}

	// Build STS client options following the functional options pattern
	var stsOpts []func(*sts.Options)

	// Set custom endpoint if provided (for testing or alternate endpoints)
	if in.STSEndpoint != "" {
		stsOpts = append(stsOpts, func(o *sts.Options) {
			o.BaseEndpoint = aws.String(in.STSEndpoint)
		})
	}

	// Create STS client using NewFromConfig pattern
	stsClient := sts.NewFromConfig(cfg, stsOpts...)

	// Capture IAM entity data if requested
	// This will create signed IAM GetRole/GetUser request
	var entityData *entityRequestData
	var err error

	if in.IncludeIAMEntity {
		entityData, err = formatSignedEntityRequest(ctx, cfg, stsClient, in)
		if err != nil {
			return nil, fmt.Errorf("failed to format signed entity request: %w", err)
		}
	}

	// Capture the signed STS GetCallerIdentity request
	// Using middleware pattern to intercept before HTTP transmission
	stsRequestData, err := captureSignedSTSRequest(ctx, stsClient, in, entityData)
	if err != nil {
		return nil, fmt.Errorf("failed to capture signed STS request: %w", err)
	}

	// Marshal headers to JSON for encoding
	headersJson, err := json.Marshal(stsRequestData.Headers)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request headers: %w", err)
	}

	// Return the signed request data as base64-encoded map
	// This matches the v1 output format for backward compatibility
	return map[string]interface{}{
		"iam_http_request_method": stsRequestData.Method,
		"iam_request_url":         base64.StdEncoding.EncodeToString([]byte(stsRequestData.URL)),
		"iam_request_headers":     base64.StdEncoding.EncodeToString(headersJson),
		"iam_request_body":        base64.StdEncoding.EncodeToString([]byte(stsRequestData.Body)),
	}, nil
}

// entityRequestData holds captured HTTP request data
type entityRequestData struct {
	Method  string
	URL     string
	Headers map[string][]string
	Body    string
}

// errRequestCaptured is a sentinel error used to stop request execution after capturing
// This prevents actual HTTP transmission while still going through the signing process
var errRequestCaptured = fmt.Errorf("request captured successfully")

// captureRequestMiddleware implements smithy-go middleware to capture signed requests
type captureRequestMiddleware struct {
	capturedRequest *entityRequestData
}

// ID returns a unique identifier for this middleware
func (m *captureRequestMiddleware) ID() string {
	return "CaptureRequestMiddleware"
}

// HandleFinalize implements the FinalizeMiddleware interface
// This runs after the request is signed but before HTTP transmission
func (m *captureRequestMiddleware) HandleFinalize(
	ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler,
) (middleware.FinalizeOutput, middleware.Metadata, error) {
	// Type assert to get the smithy HTTP request
	req, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return middleware.FinalizeOutput{}, middleware.Metadata{},
			fmt.Errorf("unexpected request type %T, expected *smithyhttp.Request", in.Request)
	}

	// Capture request details
	m.capturedRequest = &entityRequestData{
		Method:  req.Method,
		URL:     req.URL.String(),
		Headers: make(map[string][]string),
		Body:    "",
	}

	// Copy all headers from the request
	for key, values := range req.Header {
		m.capturedRequest.Headers[key] = values
	}

	// Read body using GetStream() for seekable streams
	// In v2, request bodies are streams that support seeking
	if req.GetStream() != nil {
		stream := req.GetStream()
		bodyBytes, err := io.ReadAll(stream)
		if err == nil && len(bodyBytes) > 0 {
			m.capturedRequest.Body = string(bodyBytes)
		}
	}

	// Return sentinel error to prevent actual HTTP call
	// This allows us to capture the signed request without sending it
	return middleware.FinalizeOutput{}, middleware.Metadata{}, errRequestCaptured
}

// captureSignedSTSRequest captures a signed STS GetCallerIdentity request using middleware
// It adds custom headers before signing and captures the final signed request
func captureSignedSTSRequest(ctx context.Context, stsClient *sts.Client, in *LoginInput, entityData *entityRequestData) (*entityRequestData, error) {
	// Create middleware to capture the request
	captureMiddleware := &captureRequestMiddleware{}

	// Build API options for the request
	// Following the v2 functional options pattern
	apiOpts := make([]func(*sts.Options), 0, 3)

	// Add capture middleware to Finalize stage (after signing)
	apiOpts = append(apiOpts, func(o *sts.Options) {
		o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
			return stack.Finalize.Add(captureMiddleware, middleware.After)
		})
	})

	// Add entity headers to Build stage (before signing) if provided
	if entityData != nil {
		apiOpts = append(apiOpts, func(o *sts.Options) {
			o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
				return stack.Build.Add(middleware.BuildMiddlewareFunc(
					"AddEntityHeaders",
					func(ctx context.Context, input middleware.BuildInput, next middleware.BuildHandler) (
						middleware.BuildOutput, middleware.Metadata, error,
					) {
						if req, ok := input.Request.(*smithyhttp.Request); ok {
							// Add entity request details as headers
							req.Header.Set(in.GetEntityMethodHeader, entityData.Method)
							req.Header.Set(in.GetEntityURLHeader, entityData.URL)

							// Marshal and add entity headers
							if headersJson, err := json.Marshal(entityData.Headers); err == nil {
								req.Header.Set(in.GetEntityHeadersHeader, string(headersJson))
							}
							req.Header.Set(in.GetEntityBodyHeader, entityData.Body)
						}
						return next.HandleBuild(ctx, input)
					},
				), middleware.After)
			})
		})
	}

	// Add ServerID header to Build stage (before signing) if provided
	if in.ServerIDHeaderValue != "" {
		apiOpts = append(apiOpts, func(o *sts.Options) {
			o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
				return stack.Build.Add(middleware.BuildMiddlewareFunc(
					"AddServerIDHeader",
					func(ctx context.Context, input middleware.BuildInput, next middleware.BuildHandler) (
						middleware.BuildOutput, middleware.Metadata, error,
					) {
						if req, ok := input.Request.(*smithyhttp.Request); ok {
							req.Header.Set(in.ServerIDHeaderName, in.ServerIDHeaderValue)
						}
						return next.HandleBuild(ctx, input)
					},
				), middleware.After)
			})
		})
	}

	// Call GetCallerIdentity with all configured options
	// The request will be signed and captured by our middleware
	_, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, apiOpts...)

	// Check for expected capture error or actual errors
	if err != nil && !errors.Is(err, errRequestCaptured) {
		return nil, fmt.Errorf("unexpected error during request capture: %w", err)
	}

	if captureMiddleware.capturedRequest == nil {
		return nil, fmt.Errorf("failed to capture STS request")
	}

	return captureMiddleware.capturedRequest, nil
}

// formatSignedEntityRequest creates a signed IAM GetRole or GetUser request
// This is used to include entity information in the authentication token
func formatSignedEntityRequest(ctx context.Context, cfg aws.Config, stsClient *sts.Client, in *LoginInput) (*entityRequestData, error) {

	// First, determine the IAM entity (role or user) by calling GetCallerIdentity
	// This operation requires no special permissions
	resp, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get caller identity: %w", err)
	}

	// Parse the ARN to determine entity type and name
	arn, err := responses.ParseArn(*resp.Arn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ARN: %w", err)
	}

	// Create IAM client with optional custom endpoint
	var iamOpts []func(*iam.Options)
	if in.IAMEndpoint != "" {
		iamOpts = append(iamOpts, func(o *iam.Options) {
			o.BaseEndpoint = aws.String(in.IAMEndpoint)
		})
	}
	iamClient := iam.NewFromConfig(cfg, iamOpts...)

	// Create middleware to capture the signed IAM request
	captureMiddleware := &captureRequestMiddleware{}

	// Helper function to build common API options
	buildAPIOptions := func() []func(*iam.Options) {
		opts := []func(*iam.Options){
			// Add capture middleware in Finalize stage
			func(o *iam.Options) {
				o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
					return stack.Finalize.Add(captureMiddleware, middleware.After)
				})
			},
		}

		// Add ServerID header in Build stage if provided
		if in.ServerIDHeaderValue != "" {
			opts = append(opts, func(o *iam.Options) {
				o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
					return stack.Build.Add(middleware.BuildMiddlewareFunc(
						"AddServerIDHeader",
						func(ctx context.Context, input middleware.BuildInput, next middleware.BuildHandler) (
							middleware.BuildOutput, middleware.Metadata, error,
						) {
							if req, ok := input.Request.(*smithyhttp.Request); ok {
								req.Header.Set(in.ServerIDHeaderName, in.ServerIDHeaderValue)
							}
							return next.HandleBuild(ctx, input)
						},
					), middleware.After)
				})
			})
		}

		return opts
	}

	// Make the appropriate IAM call based on entity type
	switch arn.Type {
	case "role", "assumed-role":
		_, err = iamClient.GetRole(ctx, &iam.GetRoleInput{
			RoleName: &arn.FriendlyName,
		}, buildAPIOptions()...)
	case "user":
		_, err = iamClient.GetUser(ctx, &iam.GetUserInput{
			UserName: &arn.FriendlyName,
		}, buildAPIOptions()...)
	default:
		return nil, fmt.Errorf("unsupported entity type %s, expected role or user", arn.Type)
	}

	// Check for expected capture error or actual errors
	if err != nil && !errors.Is(err, errRequestCaptured) {
		return nil, fmt.Errorf("unexpected error during IAM request capture: %w", err)
	}

	if captureMiddleware.capturedRequest == nil {
		return nil, fmt.Errorf("failed to capture IAM request")
	}

	return captureMiddleware.capturedRequest, nil
}
