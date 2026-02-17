// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iamauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/hashicorp/consul-awsauth/iamauthtest"
	"github.com/hashicorp/consul-awsauth/responses"
	"github.com/hashicorp/consul-awsauth/responsestest"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateLogin(t *testing.T) {
	f := iamauthtest.MakeFixture()

	var (
		serverForRoleMismatchedIds = &iamauthtest.Server{
			GetCallerIdentityResponse: f.ServerForRole.GetCallerIdentityResponse,
			GetRoleResponse:           responsestest.MakeGetRoleResponse(f.RoleARN, "AAAAsomenonmatchingid", responses.Tags{}),
		}
		serverForUserMismatchedIds = &iamauthtest.Server{
			GetCallerIdentityResponse: f.ServerForUser.GetCallerIdentityResponse,
			GetUserResponse:           responsestest.MakeGetUserResponse(f.UserARN, "AAAAsomenonmatchingid", responses.Tags{}),
		}
	)

	cases := map[string]struct {
		config   *Config
		server   *iamauthtest.Server
		expIdent *IdentityDetails
		expError string
	}{
		// SUCCESS CASES
		"valid role login without entity details": {
			server: f.ServerForRole,
			config: &Config{
				BoundIAMPrincipalARNs: []string{f.CanonicalRoleARN},
			},
			expIdent: &IdentityDetails{
				EntityName: f.RoleName,
				EntityId:   f.EntityID,
				AccountId:  f.AccountID,
			},
		},
		"valid user login without entity details": {
			server: f.ServerForUser,
			config: &Config{
				BoundIAMPrincipalARNs: []string{f.UserARN},
			},
			expIdent: &IdentityDetails{
				EntityName: f.UserName,
				EntityId:   f.EntityID,
				AccountId:  f.AccountID,
			},
		},
		"valid role login with entity details": {
			server: f.ServerForRole,
			config: &Config{
				BoundIAMPrincipalARNs:  []string{f.RoleARN},
				EnableIAMEntityDetails: true,
			},
			expIdent: &IdentityDetails{
				EntityName: f.RoleName,
				EntityId:   f.EntityID,
				AccountId:  f.AccountID,
				EntityPath: f.RolePath,
				EntityTags: f.RoleTags,
			},
		},
		"valid user login with entity details": {
			server: f.ServerForUser,
			config: &Config{
				BoundIAMPrincipalARNs:  []string{f.UserARN},
				EnableIAMEntityDetails: true,
			},
			expIdent: &IdentityDetails{
				EntityName: f.UserName,
				EntityId:   f.EntityID,
				AccountId:  f.AccountID,
				EntityPath: f.UserPath,
				EntityTags: f.UserTags,
			},
		},
		"valid role login with wildcard ARN": {
			server: f.ServerForRole,
			config: &Config{
				BoundIAMPrincipalARNs:  []string{f.RoleARNWildcard},
				EnableIAMEntityDetails: true,
			},
			expIdent: &IdentityDetails{
				EntityName: f.RoleName,
				EntityId:   f.EntityID,
				AccountId:  f.AccountID,
				EntityPath: f.RolePath,
				EntityTags: f.RoleTags,
			},
		},
		"valid user login with wildcard ARN": {
			server: f.ServerForUser,
			config: &Config{
				BoundIAMPrincipalARNs:  []string{f.UserARNWildcard},
				EnableIAMEntityDetails: true,
			},
			expIdent: &IdentityDetails{
				EntityName: f.UserName,
				EntityId:   f.EntityID,
				AccountId:  f.AccountID,
				EntityPath: f.UserPath,
				EntityTags: f.UserTags,
			},
		},
		// ERROR CASES
		"no bound principals": {
			expError: "not trusted",
			server:   f.ServerForRole,
			config:   &Config{},
		},
		"no matching principal": {
			expError: "not trusted",
			server:   f.ServerForUser,
			config: &Config{
				BoundIAMPrincipalARNs: []string{
					"arn:aws:iam::1234567890:user/some-other-role",
					"arn:aws:iam::1234567890:user/some-other-user",
				},
			},
		},
		"mismatched server id header": {
			expError: `expected "some-non-matching-value" but got "server.id.example.com"`,
			server:   f.ServerForRole,
			config: &Config{
				BoundIAMPrincipalARNs: []string{f.CanonicalRoleARN},
				ServerIDHeaderValue:   "some-non-matching-value",
				ServerIDHeaderName:    "X-Test-ServerID",
			},
		},
		"role unique id mismatch": {
			expError: "unique id mismatch in login token",
			// The RoleId in the GetRole response must match the UserId in the GetCallerIdentity response
			// during login. If not, the RoleId cannot be used.
			server: serverForRoleMismatchedIds,
			config: &Config{
				BoundIAMPrincipalARNs:  []string{f.RoleARN},
				EnableIAMEntityDetails: true,
			},
		},
		"user unique id mismatch": {
			expError: "unique id mismatch in login token",
			server:   serverForUserMismatchedIds,
			config: &Config{
				BoundIAMPrincipalARNs:  []string{f.UserARN},
				EnableIAMEntityDetails: true,
			},
		},
	}
	logger := hclog.New(nil)
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fakeAws := iamauthtest.NewTestServer(t, c.server)

			c.config.STSEndpoint = fakeAws.URL + "/sts"
			c.config.IAMEndpoint = fakeAws.URL + "/iam"
			setTestHeaderNames(c.config)

			// This bypasses NewAuthenticator, which bypasses config.Validate().
			auth := &Authenticator{config: c.config, logger: logger}

			loginInput := &LoginInput{
				Creds:               credentials.NewStaticCredentialsProvider("fake", "fake", ""),
				IncludeIAMEntity:    c.config.EnableIAMEntityDetails,
				STSEndpoint:         c.config.STSEndpoint,
				IAMEndpoint:         c.config.IAMEndpoint,
				STSRegion:           "fake-region",
				Logger:              logger,
				ServerIDHeaderValue: "server.id.example.com",
			}
			setLoginInputHeaderNames(loginInput)
			loginData, err := GenerateLoginData(loginInput)
			require.NoError(t, err)
			loginBytes, err := json.Marshal(loginData)
			require.NoError(t, err)

			ident, err := auth.ValidateLogin(context.Background(), string(loginBytes))
			if c.expError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), c.expError)
				require.Nil(t, ident)
			} else {
				require.NoError(t, err)
				require.Equal(t, c.expIdent, ident)
			}
		})
	}
}

func setLoginInputHeaderNames(in *LoginInput) {
	in.ServerIDHeaderName = "X-Test-ServerID"
	in.GetEntityMethodHeader = "X-Test-Method"
	in.GetEntityURLHeader = "X-Test-URL"
	in.GetEntityHeadersHeader = "X-Test-Headers"
	in.GetEntityBodyHeader = "X-Test-Body"
}

func TestGenerateLoginDataValidation(t *testing.T) {
	logger := hclog.New(nil)

	cases := map[string]struct {
		loginInput *LoginInput
		expError   string
	}{
		"nil input": {
			loginInput: nil,
			expError:   "LoginInput cannot be nil",
		},
		"missing credentials": {
			loginInput: &LoginInput{
				STSRegion: "us-west-2",
				Logger:    logger,
			},
			expError: "credentials provider is required",
		},
		"missing STS region": {
			loginInput: &LoginInput{
				Creds:  credentials.NewStaticCredentialsProvider("fake", "fake", ""),
				Logger: logger,
			},
			expError: "STS region is required",
		},
		"IncludeIAMEntity true but missing GetEntityMethodHeader": {
			loginInput: &LoginInput{
				Creds:                  credentials.NewStaticCredentialsProvider("fake", "fake", ""),
				STSRegion:              "us-west-2",
				IncludeIAMEntity:       true,
				Logger:                 logger,
				GetEntityURLHeader:     "X-Test-URL",
				GetEntityHeadersHeader: "X-Test-Headers",
				GetEntityBodyHeader:    "X-Test-Body",
			},
			expError: "GetEntityMethodHeader is required when IncludeIAMEntity is true",
		},
		"IncludeIAMEntity true but missing GetEntityURLHeader": {
			loginInput: &LoginInput{
				Creds:                  credentials.NewStaticCredentialsProvider("fake", "fake", ""),
				STSRegion:              "us-west-2",
				IncludeIAMEntity:       true,
				Logger:                 logger,
				GetEntityMethodHeader:  "X-Test-Method",
				GetEntityHeadersHeader: "X-Test-Headers",
				GetEntityBodyHeader:    "X-Test-Body",
			},
			expError: "GetEntityURLHeader is required when IncludeIAMEntity is true",
		},
		"IncludeIAMEntity true but missing GetEntityHeadersHeader": {
			loginInput: &LoginInput{
				Creds:                 credentials.NewStaticCredentialsProvider("fake", "fake", ""),
				STSRegion:             "us-west-2",
				IncludeIAMEntity:      true,
				Logger:                logger,
				GetEntityMethodHeader: "X-Test-Method",
				GetEntityURLHeader:    "X-Test-URL",
				GetEntityBodyHeader:   "X-Test-Body",
			},
			expError: "GetEntityHeadersHeader is required when IncludeIAMEntity is true",
		},
		"IncludeIAMEntity true but missing GetEntityBodyHeader": {
			loginInput: &LoginInput{
				Creds:                  credentials.NewStaticCredentialsProvider("fake", "fake", ""),
				STSRegion:              "us-west-2",
				IncludeIAMEntity:       true,
				Logger:                 logger,
				GetEntityMethodHeader:  "X-Test-Method",
				GetEntityURLHeader:     "X-Test-URL",
				GetEntityHeadersHeader: "X-Test-Headers",
			},
			expError: "GetEntityBodyHeader is required when IncludeIAMEntity is true",
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := GenerateLoginData(c.loginInput)
			require.Error(t, err)
			require.Contains(t, err.Error(), c.expError)
		})
	}
}

func TestValidateHeaderValueWithRequest(t *testing.T) {
	cases := map[string]struct {
		req           *http.Request
		headers       http.Header
		headerName    string
		requiredValue string
		expError      string
	}{
		"valid header with authorization": {
			headers: http.Header{
				"X-Test-Header": []string{"expected-value"},
				"Authorization": []string{"AWS4-HMAC-SHA256 Credential=..., SignedHeaders=host;x-test-header, Signature=..."},
			},
			headerName:    "X-Test-Header",
			requiredValue: "expected-value",
			expError:      "",
		},
		"missing required header": {
			headers:       http.Header{},
			headerName:    "X-Test-Header",
			requiredValue: "expected-value",
			expError:      `missing header "X-Test-Header"`,
		},
		"wrong header value": {
			headers: http.Header{
				"X-Test-Header": []string{"wrong-value"},
				"Authorization": []string{"AWS4-HMAC-SHA256 Credential=..., SignedHeaders=host;x-test-header, Signature=..."},
			},
			headerName:    "X-Test-Header",
			requiredValue: "expected-value",
			expError:      `expected "expected-value" but got "wrong-value"`,
		},
		"header not signed": {
			headers: http.Header{
				"X-Test-Header": []string{"expected-value"},
				"Authorization": []string{"AWS4-HMAC-SHA256 Credential=..., SignedHeaders=host;other-header, Signature=..."},
			},
			headerName:    "X-Test-Header",
			requiredValue: "expected-value",
			expError:      "header wasn't signed",
		},
		"missing authorization header": {
			headers: http.Header{
				"X-Test-Header": []string{"expected-value"},
			},
			headerName:    "X-Test-Header",
			requiredValue: "expected-value",
			expError:      "missing Authorization header",
		},
		"authorization via query params - any params rejected": {
			req: &http.Request{
				URL: &url.URL{RawQuery: "X-Amz-SignedHeaders=host%3Bx-test-header"},
			},
			headers: http.Header{
				"X-Test-Header": []string{"expected-value"},
			},
			headerName:    "X-Test-Header",
			requiredValue: "expected-value",
			expError:      "URL query parameters are not allowed for header validation",
		},
		"any query params should be rejected": {
			req: &http.Request{
				URL: &url.URL{RawQuery: "foo=bar&test=123"},
			},
			headers: http.Header{
				"X-Test-Header": []string{"expected-value"},
			},
			headerName:    "X-Test-Header",
			requiredValue: "expected-value",
			expError:      "URL query parameters are not allowed for header validation",
		},
		"authorization bypass attempt - algorithm in query": {
			req: &http.Request{
				URL: &url.URL{RawQuery: "X-Amz-Algorithm=AWS4-HMAC-SHA256"},
			},
			headers: http.Header{
				"X-Test-Header": []string{"expected-value"},
			},
			headerName:    "X-Test-Header",
			requiredValue: "expected-value",
			expError:      "URL query parameters are not allowed for header validation",
		},
		"authorization bypass attempt - credential in query": {
			req: &http.Request{
				URL: &url.URL{RawQuery: "X-Amz-Credential=fake-credential"},
			},
			headers: http.Header{
				"X-Test-Header": []string{"expected-value"},
			},
			headerName:    "X-Test-Header",
			requiredValue: "expected-value",
			expError:      "URL query parameters are not allowed for header validation",
		},
		"authorization bypass attempt - multiple auth params": {
			req: &http.Request{
				URL: &url.URL{RawQuery: "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20220322T211103Z"},
			},
			headers: http.Header{
				"X-Test-Header": []string{"expected-value"},
			},
			headerName:    "X-Test-Header",
			requiredValue: "expected-value",
			expError:      "URL query parameters are not allowed for header validation",
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateHeaderValueWithRequest(c.req, c.headers, c.headerName, c.requiredValue)
			if c.expError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), c.expError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
