// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iamauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"context"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hashicorp/consul-awsauth/responses"
	"github.com/hashicorp/go-hclog"
)

type LoginInput struct {
	// Creds is the AWS credentials provider (replaces v1's *credentials.Credentials)
	// In v2, use credentials.NewStaticCredentialsProvider, ec2rolecreds.New(), etc.
	Creds            aws.CredentialsProvider
	IncludeIAMEntity bool
	STSEndpoint      string
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
// https://github.com/hashicorp/go-secure-stdlib/blob/main/awsutil/generate_credentials.go#L232-L301
func GenerateLoginData(in *LoginInput) (map[string]interface{}, error) {
	ctx := context.Background()

	// Build AWS config from credentials provider
	cfg := aws.Config{
		Credentials: in.Creds,
		// These are empty strings by default (i.e. not enabled)
		Region:              aws.String(in.STSRegion),
		Endpoint:            aws.String(in.STSEndpoint),
		STSRegionalEndpoint: aws.RegionalSTSEndpoint,
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile("my-application-profile"),
	)

	svc := sts.New(cfg)
	stsRequest, _ := svc.GetCallerIdentityRequest(nil)

	// Include the iam:GetRole or iam:GetUser request in headers.
	if in.IncludeIAMEntity {
		entityRequest, err := formatSignedEntityRequest(svc, in)
		if err != nil {
			return nil, err
		}
		if in.STSEndpoint != "" {
			o.BaseEndpoint = aws.String(in.STSEndpoint)
		}
	})

	// Capture the signed STS GetCallerIdentity request
	var entityData *entityRequestData
	var err error

	// If we need IAM entity details, capture them first
	if in.IncludeIAMEntity {
		entityData, err = formatSignedEntityRequest(cfg, stsClient, in)
		if err != nil {
			return nil, err
		}
	}

	// Now capture the STS request with entity headers if needed
	// ServerIDHeaderValue will be added inside captureSignedSTSRequest before signing
	stsRequestData, err := captureSignedSTSRequest(ctx, stsClient, in, entityData)
	if err != nil {
		return nil, err
	}

	// Now extract out the relevant parts of the request
	headersJson, err := json.Marshal(stsRequestData.Headers)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"iam_http_request_method": stsRequestData.Method,
		"iam_request_url":         base64.StdEncoding.EncodeToString([]byte(stsRequestData.URL)),
		"iam_request_headers":     base64.StdEncoding.EncodeToString(headersJson),
		"iam_request_body":        base64.StdEncoding.EncodeToString([]byte(stsRequestData.Body)),
	}, nil
}

type entityRequestData struct {
	Method  string
	URL     string
	Headers map[string][]string
	Body    string
}

// Special error to signal that we captured the request successfully
var errRequestCaptured = fmt.Errorf("request captured successfully")

// captureRequestMiddleware captures the signed HTTP request without sending it
type captureRequestMiddleware struct {
	capturedRequest *entityRequestData
}

func (m *captureRequestMiddleware) ID() string {
	return "captureRequestMiddleware"
}

func (m *captureRequestMiddleware) HandleFinalize(
	ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler,
) (middleware.FinalizeOutput, middleware.Metadata, error) {
	// Extract the HTTP request
	req, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return middleware.FinalizeOutput{}, middleware.Metadata{}, fmt.Errorf("unexpected request type %T", in.Request)
	}

	// Capture request details
	m.capturedRequest = &entityRequestData{
		Method:  req.Method,
		URL:     req.URL.String(),
		Headers: make(map[string][]string),
		Body:    "",
	}

	// Copy headers
	for key, values := range req.Header {
		m.capturedRequest.Headers[key] = values
	}

	// Read body if present - need to handle GetStream for seekable bodies
	if req.GetStream() != nil {
		stream := req.GetStream()
		bodyBytes, err := io.ReadAll(stream)
		if err == nil && len(bodyBytes) > 0 {
			m.capturedRequest.Body = string(bodyBytes)
		}
	}

	// Return our special error to stop the pipeline without making the actual HTTP call
	return middleware.FinalizeOutput{}, middleware.Metadata{}, errRequestCaptured
}

func captureSignedSTSRequest(ctx context.Context, stsClient *sts.Client, in *LoginInput, entityData *entityRequestData) (*entityRequestData, error) {
	// Create middleware to capture the request
	captureMiddleware := &captureRequestMiddleware{}

	// Call GetCallerIdentity with middleware to capture the signed request
	_, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, func(o *sts.Options) {
		o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
			// Add middleware to capture the signed request
			return stack.Finalize.Add(captureMiddleware, middleware.After)
		})

		// Add entity headers if provided (these need to be signed)
		if entityData != nil {
			o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
				return stack.Build.Add(middleware.BuildMiddlewareFunc(
					"AddEntityHeaders",
					func(ctx context.Context, input middleware.BuildInput, next middleware.BuildHandler) (
						middleware.BuildOutput, middleware.Metadata, error,
					) {
						req, ok := input.Request.(*smithyhttp.Request)
						if ok {
							req.Header.Set(in.GetEntityMethodHeader, entityData.Method)
							req.Header.Set(in.GetEntityURLHeader, entityData.URL)

							headersJson, _ := json.Marshal(entityData.Headers)
							req.Header.Set(in.GetEntityHeadersHeader, string(headersJson))
							req.Header.Set(in.GetEntityBodyHeader, entityData.Body)
						}
						return next.HandleBuild(ctx, input)
					},
				), middleware.After)
			})
		}
		// Add ServerIDHeaderValue header if provided - must be signed
		if in.ServerIDHeaderValue != "" {
			o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
				return stack.Build.Add(middleware.BuildMiddlewareFunc(
					"AddServerIDHeader",
					func(ctx context.Context, input middleware.BuildInput, next middleware.BuildHandler) (
						middleware.BuildOutput, middleware.Metadata, error,
					) {
						req, ok := input.Request.(*smithyhttp.Request)
						if ok {
							req.Header.Set(in.ServerIDHeaderName, in.ServerIDHeaderValue)
						}
						return next.HandleBuild(ctx, input)
					},
				), middleware.After)
			})
		}
	})

	// We expect our special error indicating the request was captured
	if err != nil && !errors.Is(err, errRequestCaptured) && err.Error() != errRequestCaptured.Error() {
		return nil, err
	}

	if captureMiddleware.capturedRequest == nil {
		return nil, fmt.Errorf("failed to capture STS request")
	}

	return captureMiddleware.capturedRequest, nil
}

func formatSignedEntityRequest(cfg aws.Config, stsClient *sts.Client, in *LoginInput) (*entityRequestData, error) {
	ctx := context.Background()

	// We need to retrieve the IAM user or role for the iam:GetRole or iam:GetUser request.
	// GetCallerIdentity returns this and requires no permissions.
	resp, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}

	arn, err := responses.ParseArn(*resp.Arn)
	if err != nil {
		return nil, err
	}

	// Create IAM client from the same config
	iamClient := iam.NewFromConfig(cfg)

	// Create middleware to capture the request
	captureMiddleware := &captureRequestMiddleware{}

	// Add the capture middleware to intercept before sending
	switch arn.Type {
	case "role", "assumed-role":
		_, err = iamClient.GetRole(ctx, &iam.GetRoleInput{
			RoleName: &arn.FriendlyName,
		}, func(o *iam.Options) {
			o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
				// Add middleware to capture the signed request
				return stack.Finalize.Add(captureMiddleware, middleware.After)
			})
			// Inject server ID header if provided
			if in.ServerIDHeaderValue != "" {
				o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
					return stack.Build.Add(middleware.BuildMiddlewareFunc(
						"AddServerIDHeader",
						func(ctx context.Context, input middleware.BuildInput, next middleware.BuildHandler) (
							middleware.BuildOutput, middleware.Metadata, error,
						) {
							req, ok := input.Request.(*smithyhttp.Request)
							if ok {
								req.Header.Set(in.ServerIDHeaderName, in.ServerIDHeaderValue)
							}
							return next.HandleBuild(ctx, input)
						},
					), middleware.After)
				})
			}
		})
	case "user":
		_, err = iamClient.GetUser(ctx, &iam.GetUserInput{
			UserName: &arn.FriendlyName,
		}, func(o *iam.Options) {
			o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
				return stack.Finalize.Add(captureMiddleware, middleware.After)
			})
			// Inject server ID header if provided
			if in.ServerIDHeaderValue != "" {
				o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
					return stack.Build.Add(middleware.BuildMiddlewareFunc(
						"AddServerIDHeader",
						func(ctx context.Context, input middleware.BuildInput, next middleware.BuildHandler) (
							middleware.BuildOutput, middleware.Metadata, error,
						) {
							req, ok := input.Request.(*smithyhttp.Request)
							if ok {
								req.Header.Set(in.ServerIDHeaderName, in.ServerIDHeaderValue)
							}
							return next.HandleBuild(ctx, input)
						},
					), middleware.After)
				})
			}
		})
	default:
		return nil, fmt.Errorf("entity %s is not an IAM role or IAM user", arn.Type)
	}

	// We expect our special error indicating the request was captured
	// Any other error is a real problem
	if err != nil && !errors.Is(err, errRequestCaptured) && err.Error() != errRequestCaptured.Error() {
		return nil, err
	}

	if captureMiddleware.capturedRequest == nil {
		return nil, fmt.Errorf("failed to capture IAM request")
	}

	return captureMiddleware.capturedRequest, nil
}
