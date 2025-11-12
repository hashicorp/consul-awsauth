// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iamauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hashicorp/consul-awsauth/responses"
	"github.com/hashicorp/go-hclog"
)

type LoginInput struct {
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
// Updated for AWS SDK v2 from https://github.com/hashicorp/go-secure-stdlib/blob/main/awsutil/generate_credentials.go#L232-L301
func GenerateLoginData(in *LoginInput) (map[string]interface{}, error) {
	ctx := context.Background()
	
	cfg := aws.Config{
		Credentials: in.Creds,
		Region:      in.STSRegion,
	}
	
	// Set custom endpoint if provided
	if in.STSEndpoint != "" {
		cfg.EndpointResolver = aws.EndpointResolverFunc(func(service, region string) (aws.Endpoint, error) {
			if service == sts.ServiceID {
				return aws.Endpoint{URL: in.STSEndpoint}, nil
			}
			return aws.Endpoint{}, &aws.EndpointNotFoundError{}
		})
	}

	stsClient := sts.NewFromConfig(cfg)

	// Create a GetCallerIdentity request
	callerReq, err := createSignedGetCallerIdentityRequest(ctx, stsClient, in)
	if err != nil {
		return nil, err
	}

	// Include the iam:GetRole or iam:GetUser request in headers if requested
	if in.IncludeIAMEntity {
		entityRequest, err := createSignedEntityRequest(ctx, stsClient, cfg, in)
		if err != nil {
			return nil, err
		}

		headersJson, err := json.Marshal(entityRequest.Header)
		if err != nil {
			return nil, err
		}
		requestBody, err := io.ReadAll(entityRequest.Body)
		if err != nil {
			return nil, err
		}

		callerReq.Header.Set(in.GetEntityMethodHeader, entityRequest.Method)
		callerReq.Header.Set(in.GetEntityURLHeader, entityRequest.URL.String())
		callerReq.Header.Set(in.GetEntityHeadersHeader, string(headersJson))
		callerReq.Header.Set(in.GetEntityBodyHeader, string(requestBody))
	}

	// Extract the relevant parts of the request
	headersJson, err := json.Marshal(callerReq.Header)
	if err != nil {
		return nil, err
	}
	requestBody, err := io.ReadAll(callerReq.Body)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"iam_http_request_method": callerReq.Method,
		"iam_request_url":         base64.StdEncoding.EncodeToString([]byte(callerReq.URL.String())),
		"iam_request_headers":     base64.StdEncoding.EncodeToString(headersJson),
		"iam_request_body":        base64.StdEncoding.EncodeToString(requestBody),
	}, nil
}

func createSignedGetCallerIdentityRequest(ctx context.Context, stsClient *sts.Client, in *LoginInput) (*http.Request, error) {
	// Determine endpoint
	endpoint := "https://sts.amazonaws.com/"
	if in.STSEndpoint != "" {
		endpoint = in.STSEndpoint
	}
	if !strings.HasSuffix(endpoint, "/") {
		endpoint += "/"
	}
	
	// Create form data for STS GetCallerIdentity
	formData := url.Values{
		"Action":  []string{"GetCallerIdentity"},
		"Version": []string{"2011-06-15"},
	}
	
	body := strings.NewReader(formData.Encode())
	
	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, body)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	
	// Add custom headers if needed
	if in.ServerIDHeaderValue != "" && in.ServerIDHeaderName != "" {
		req.Header.Set(in.ServerIDHeaderName, in.ServerIDHeaderValue)
	}
	
	// Get credentials and sign the request
	creds, err := in.Creds.Retrieve(ctx)
	if err != nil {
		return nil, err
	}
	
	signer := v4.NewSigner()
	err = signer.SignHTTP(ctx, creds, req, "", "sts", in.STSRegion, time.Now())
	if err != nil {
		return nil, err
	}
	
	return req, nil
}

func createSignedEntityRequest(ctx context.Context, stsClient *sts.Client, cfg aws.Config, in *LoginInput) (*http.Request, error) {
	// First, get caller identity to determine the entity type
	callerResp, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}

	arn, err := responses.ParseArn(*callerResp.Arn)
	if err != nil {
		return nil, err
	}

	// Create IAM request endpoint
	endpoint := "https://iam.amazonaws.com/"
	
	var formData url.Values
	switch arn.Type {
	case "role", "assumed-role":
		formData = url.Values{
			"Action":   []string{"GetRole"},
			"RoleName": []string{arn.FriendlyName},
			"Version":  []string{"2010-05-08"},
		}
	case "user":
		formData = url.Values{
			"Action":   []string{"GetUser"},
			"UserName": []string{arn.FriendlyName},
			"Version":  []string{"2010-05-08"},
		}
	default:
		return nil, fmt.Errorf("entity %s is not an IAM role or IAM user", arn.Type)
	}
	
	body := strings.NewReader(formData.Encode())
	
	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, body)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	
	// Add custom headers if needed
	if in.ServerIDHeaderValue != "" && in.ServerIDHeaderName != "" {
		req.Header.Set(in.ServerIDHeaderName, in.ServerIDHeaderValue)
	}
	
	// Get credentials and sign the request
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}
	
	signer := v4.NewSigner()
	err = signer.SignHTTP(ctx, creds, req, "", "iam", cfg.Region, time.Now())
	if err != nil {
		return nil, err
	}

	return req, nil
}
