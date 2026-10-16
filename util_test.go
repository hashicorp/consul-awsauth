// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package iamauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/hashicorp/consul-awsauth/iamauthtest"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

// fipsConfigSource stands in for the config source config.LoadDefaultConfig builds from
// AWS_USE_FIPS_ENDPOINT / use_fips_endpoint.
type fipsConfigSource struct{}

func (fipsConfigSource) GetUseFIPSEndpoint(context.Context) (aws.FIPSEndpointState, bool, error) {
	return aws.FIPSEndpointStateEnabled, true, nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// decodeLoginData returns the signed STS request URL and headers from GenerateLoginData output.
func decodeLoginData(t *testing.T, data map[string]interface{}) (*url.URL, http.Header) {
	t.Helper()
	rawURL, err := base64.StdEncoding.DecodeString(data["iam_request_url"].(string))
	require.NoError(t, err)
	u, err := url.Parse(string(rawURL))
	require.NoError(t, err)

	rawHeaders, err := base64.StdEncoding.DecodeString(data["iam_request_headers"].(string))
	require.NoError(t, err)
	var headers http.Header
	require.NoError(t, json.Unmarshal(rawHeaders, &headers))
	return u, headers
}

func TestGenerateLoginData_ConfigFIPS(t *testing.T) {
	f := iamauthtest.MakeFixture()
	callerIdentity, err := xml.Marshal(f.ServerForRole.GetCallerIdentityResponse)
	require.NoError(t, err)

	var requestedHosts []string
	httpClient := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		requestedHosts = append(requestedHosts, r.URL.Host)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/xml"}},
			Body:       io.NopCloser(bytes.NewReader(callerIdentity)),
			Request:    r,
		}, nil
	})}

	baseConfig := &aws.Config{
		HTTPClient:    httpClient,
		ConfigSources: []interface{}{fipsConfigSource{}},
		// Region and Credentials from the base config must not override LoginInput.
		Region:      "eu-west-1",
		Credentials: credentials.NewStaticCredentialsProvider("AKIDBASECONFIG", "base-secret", ""),
	}

	in := &LoginInput{
		Creds:               credentials.NewStaticCredentialsProvider("AKIDLOGININPUT", "secret", ""),
		IncludeIAMEntity:    true,
		STSRegion:           "us-west-2",
		Config:              baseConfig,
		Logger:              hclog.NewNullLogger(),
		ServerIDHeaderValue: "server.id.example.com",
	}
	setLoginInputHeaderNames(in)

	data, err := GenerateLoginData(in)
	require.NoError(t, err)

	// The only request actually sent (GetCallerIdentity lookup) used the base config's HTTP client and FIPS endpoint.
	require.Equal(t, []string{"sts-fips.us-west-2.amazonaws.com"}, requestedHosts)

	stsURL, headers := decodeLoginData(t, data)
	require.Equal(t, "sts-fips.us-west-2.amazonaws.com", stsURL.Host)
	require.Contains(t, headers.Get("Authorization"), "Credential=AKIDLOGININPUT/")
	require.Contains(t, headers.Get("Authorization"), "/us-west-2/sts/aws4_request")

	// IAM is global: the FIPS endpoint must still be signed for us-east-1, not the STS region.
	iamURL, err := url.Parse(headers.Get(in.GetEntityURLHeader))
	require.NoError(t, err)
	require.Equal(t, "iam-fips.amazonaws.com", iamURL.Host)
	var entityHeaders http.Header
	require.NoError(t, json.Unmarshal([]byte(headers.Get(in.GetEntityHeadersHeader)), &entityHeaders))
	require.Contains(t, entityHeaders.Get("Authorization"), "Credential=AKIDLOGININPUT/")
	require.Contains(t, entityHeaders.Get("Authorization"), "/us-east-1/iam/aws4_request")

	require.Equal(t, "eu-west-1", baseConfig.Region, "base config must not be modified")
}

func TestGenerateLoginData_ConfigHTTPClient(t *testing.T) {
	f := iamauthtest.MakeFixture()
	// TLS server with a self-signed certificate, like an endpoint behind a proxy with a private CA.
	srv := iamauthtest.NewTLSTestServer(t, f.ServerForRole)

	newInput := func(cfg *aws.Config) *LoginInput {
		in := &LoginInput{
			Creds:            credentials.NewStaticCredentialsProvider("fake", "fake", ""),
			IncludeIAMEntity: true,
			STSEndpoint:      srv.URL + "/sts",
			STSRegion:        "us-east-1",
			Config:           cfg,
			Logger:           hclog.NewNullLogger(),
		}
		setLoginInputHeaderNames(in)
		return in
	}

	t.Run("without Config the private CA is not trusted", func(t *testing.T) {
		_, err := GenerateLoginData(newInput(nil))
		require.Error(t, err)
		require.Contains(t, err.Error(), "certificate")
	})

	t.Run("Config HTTP client that trusts the CA is used", func(t *testing.T) {
		_, err := GenerateLoginData(newInput(&aws.Config{HTTPClient: srv.Client()}))
		require.NoError(t, err)
	})
}
