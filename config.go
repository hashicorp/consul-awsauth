// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iamauth

import (
	"fmt"
	"strings"
	awsArn "github.com/aws/aws-sdk-go-v2/aws/arn"
)

type Config struct {
	BoundIAMPrincipalARNs  []string
	EnableIAMEntityDetails bool
	IAMEntityTags          []string
	ServerIDHeaderValue    string
	MaxRetries             int
	IAMEndpoint            string
	STSEndpoint            string
	AllowedSTSHeaderValues []string

	// Customizable header names
	ServerIDHeaderName     string
	GetEntityMethodHeader  string
	GetEntityURLHeader     string
	GetEntityHeadersHeader string
	GetEntityBodyHeader    string
}

func (c *Config) Validate() error {
	if len(c.BoundIAMPrincipalARNs) == 0 {
		return fmt.Errorf("BoundIAMPrincipalARNs is required and must have at least 1 entry")
	}

	for _, principalArn := range c.BoundIAMPrincipalARNs {
		if n := strings.Count(principalArn, "*"); n > 0 {
			if !c.EnableIAMEntityDetails {
				return fmt.Errorf("Must set EnableIAMEntityDetails=true to use wildcards in BoundIAMPrincipalARNs")
			}
			if n != 1 || !strings.HasSuffix(principalArn, "*") {
				return fmt.Errorf("Only one wildcard is allowed at the end of the bound IAM principal ARN")
			}
		}

		if parsed, err := awsArn.Parse(principalArn); err != nil {
			return fmt.Errorf("Invalid principal ARN: %q", principalArn)
		} else if parsed.Service != "iam" && parsed.Service != "sts" {
			return fmt.Errorf("Invalid principal ARN: %q", principalArn)
		}
	}

	if len(c.IAMEntityTags) > 0 && !c.EnableIAMEntityDetails {
		return fmt.Errorf("Must set EnableIAMEntityDetails=true to use IAMUserTags")
	}

	// If server id header checking is enabled, we need the header name.
	if c.ServerIDHeaderValue != "" && c.ServerIDHeaderName == "" {
		return fmt.Errorf("Must set ServerIDHeaderName to use a server ID value")
	}

	if c.EnableIAMEntityDetails && (c.GetEntityBodyHeader == "" ||
		c.GetEntityHeadersHeader == "" ||
		c.GetEntityMethodHeader == "" ||
		c.GetEntityURLHeader == "") {
		return fmt.Errorf("Must set all of GetEntityMethodHeader, GetEntityURLHeader, " +
			"GetEntityHeadersHeader, and GetEntityBodyHeader when EnableIAMEntityDetails=true")
	}

	if c.STSEndpoint != "" {
		if _, err := parseUrl(c.STSEndpoint); err != nil {
			return fmt.Errorf("STSEndpoint is invalid: %s", err)
		}
	}

	if c.IAMEndpoint != "" {
		if _, err := parseUrl(c.IAMEndpoint); err != nil {
			return fmt.Errorf("IAMEndpoint is invalid: %s", err)
		}
	}

	return nil
}
