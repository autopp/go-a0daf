package auth_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/autopp/go-a0daf/pkg/auth"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("DeviceAuthFlow", func() {
	clientID := "clientID"

	Describe("FetchDeviceCode()", func() {
		scope := "openid profile"
		audience := "https://example.com/api"

		It("returns DeviceCodeResponse when succeeded", func() {
			// Arrange
			deviceCode := "device_code"
			userCode := "123456"
			verificationURI := "https://example.com/activate"
			verificationURIComplete := verificationURI + "/?user_code=" + userCode
			expiresIn := 900
			interval := 5
			ms := newMockServer([]requestExpectation{
				{
					path: "/oauth/device/code",
					form: map[string][]string{
						"client_id": {clientID},
						"scope":     {scope},
						"audience":  {audience},
					},
					statusCode: 200,
					responseBody: fmt.Sprintf(`{
						"device_code": "%s",
						"user_code": "%s",
						"verification_uri": "%s",
						"verification_uri_complete": "%s",
						"expires_in": %d,
						"interval": %d
					}`, deviceCode, userCode, verificationURI, verificationURIComplete, expiresIn, interval),
				},
			})
			defer ms.Close()

			// Act
			daf, err := auth.NewDeviceAuthFlow(auth.WithBaseURL(ms.URL), auth.WithClientID(clientID))
			if err != nil {
				panic(err)
			}
			actual, err := daf.FetchDeviceCode(scope, audience)

			// Assert
			Expect(err).NotTo(HaveOccurred())
			Expect(actual).To(Equal(&auth.DeviceCodeResponse{
				DeviceCode:              deviceCode,
				UserCode:                userCode,
				VerificationURI:         verificationURI,
				VerificationURIComplete: verificationURIComplete,
				ExpiresIn:               expiresIn,
				Interval:                interval,
			}))
			Expect(ms.restExpects()).To(BeEmpty())
		})

		It("returns APIError when 4xx occured", func() {
			// Arrange
			statusCode := 403
			errorCode := "unauthorized_client"
			errorDescription := "Unauthorized or unknown client"
			ms := newMockServer([]requestExpectation{
				{
					path: "/oauth/device/code",
					form: map[string][]string{
						"client_id": {clientID},
						"scope":     {scope},
						"audience":  {audience},
					},
					statusCode: statusCode,
					responseBody: fmt.Sprintf(`{
						"error": "%s",
						"error_description": "%s"
					}`, errorCode, errorDescription),
				},
			})
			defer ms.Close()

			// Act
			daf, err := auth.NewDeviceAuthFlow(auth.WithBaseURL(ms.URL), auth.WithClientID(clientID))
			if err != nil {
				panic(err)
			}
			_, err = daf.FetchDeviceCode(scope, audience)

			// Assert
			Expect(err).To(MatchError(&auth.APIError{
				StatusCode: statusCode,
				Body:       &auth.ErrorResponse{Error: errorCode, ErrorDescription: errorDescription}},
			))
			Expect(ms.restExpects()).To(BeEmpty())
		})
	})
})

// stub auth0 api
type requestExpectation struct {
	path         string
	form         map[string][]string
	statusCode   int
	responseBody string
}

type mockServer struct {
	*httptest.Server
	nextReq int
	expects []requestExpectation
}

func newMockServer(expects []requestExpectation) *mockServer {
	ms := &mockServer{
		nextReq: 0,
		expects: expects,
	}

	formatRequest := func(r *http.Request) string {
		forms := make([]string, 0)
		for k, vs := range r.PostForm {
			for _, v := range vs {
				forms = append(forms, fmt.Sprintf("%s=%s", k, v))
			}
		}
		return fmt.Sprintf("unexpected request: %s %s (%s)", r.Method, r.URL.String(), strings.Join(forms, "; "))
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer GinkgoRecover()
		if ms.nextReq >= len(ms.expects) {
			Fail(formatRequest(r))
			return
		}
		Expect(ms.nextReq).To(BeNumerically("<", len(ms.expects)), "over requests")

		r.ParseForm()
		expected := expects[ms.nextReq]
		type request struct {
			method string
			path   string
			form   map[string][]string
		}
		Expect(request{
			method: r.Method,
			path:   r.URL.Path,
			form:   map[string][]string(r.PostForm)},
		).To(Equal(request{
			method: "POST",
			path:   expected.path,
			form:   expected.form,
		}), "unexpected request")

		w.WriteHeader(expected.statusCode)
		w.Header().Add("content-type", "application/json")
		w.Write([]byte(expected.responseBody))

		ms.nextReq++
	}))

	ms.Server = ts

	return ms
}

func (ms *mockServer) restExpects() []requestExpectation {
	return ms.expects[ms.nextReq:]
}
