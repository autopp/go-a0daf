package auth_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/autopp/go-a0daf/pkg/auth"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("DeviceAuthFlow", func() {
	clientID := "clientID"

	Describe("FetchDeviceCode()", func() {
		scope := "openid profile"
		audience := "https://example.com/api"

		deviceCode := "device_code"
		userCode := "123456"
		verificationURI := "https://example.com/activate"
		verificationURIComplete := verificationURI + "/?user_code=" + userCode
		expiresIn := 20
		interval := 5

		It("returns DeviceCodeResponse when succeeded", func() {
			// Arrange
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

			timeNow := newStubTimeNow(9)
			daf, err := auth.NewDeviceAuthFlow(
				auth.WithBaseURL(ms.URL),
				auth.WithClientID(clientID),
				auth.WithTimeNow(timeNow),
			)
			if err != nil {
				panic(err)
			}

			// Act
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
				ExpiresAt:               baseStubTime.Add(time.Duration(expiresIn) * time.Second),
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

	Describe("PollToken()", func() {
		apiPath := "/oauth/token"
		deviceCode := "device_code"
		userCode := "123456"
		verificationURI := "https://example.com/activate"
		verificationURIComplete := verificationURI + "/?user_code=" + userCode
		expiresIn := 20
		interval := 5
		intervalD := time.Duration(interval) * time.Second

		dc := &auth.DeviceCodeResponse{
			DeviceCode:              deviceCode,
			UserCode:                userCode,
			VerificationURI:         verificationURI,
			VerificationURIComplete: verificationURIComplete,
			ExpiresIn:               expiresIn,
			Interval:                interval,
			ExpiresAt:               baseStubTime.Add(time.Duration(expiresIn) * time.Second),
		}

		expectedForm := map[string][]string{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {deviceCode},
			"client_id":   {clientID},
		}
		authorizationPending := requestExpectation{
			path:         apiPath,
			form:         expectedForm,
			statusCode:   401,
			responseBody: `{"error": "authorization_pending", "error_description": "authorization pending"}`,
		}

		It("returns token when authorized", func() {
			// Arrange
			accessToken := "access_token"
			refreshToken := "refresh_token"
			idToken := "id_token"
			tokenExpiresIn := 86400
			ms := newMockServer([]requestExpectation{
				authorizationPending,
				authorizationPending,
				{
					path:       apiPath,
					form:       expectedForm,
					statusCode: 200,
					responseBody: fmt.Sprintf(`{
						"access_token": "%s",
						"refresh_token": "%s",
						"id_token": "%s",
						"token_type": "Bearer",
						"expires_in": %d
					}`, accessToken, refreshToken, idToken, tokenExpiresIn),
				},
			})
			defer ms.Close()

			timeNow := newStubTimeNow(interval)
			timeSleep := newMockTimeSleep()
			daf, _ := auth.NewDeviceAuthFlow(
				auth.WithBaseURL(ms.URL),
				auth.WithClientID(clientID),
				auth.WithTimeNow(timeNow),
				auth.WithTimeSleep(timeSleep.f),
			)

			// Act
			actual, err := daf.PollToken(dc)

			// Assert
			Expect(err).NotTo(HaveOccurred())
			Expect(actual).To(Equal(&auth.TokenResponse{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				IdToken:      idToken,
				TokenType:    "Bearer",
				ExpiresIn:    tokenExpiresIn,
			}))
			Expect(ms.restExpects()).To(BeEmpty())
			Expect(timeSleep.calls).To(Equal([]time.Duration{intervalD, intervalD}))
		})

		It("returns ExpiredError when authorization was expired", func() {
			// Arrange
			ms := newMockServer([]requestExpectation{
				authorizationPending,
				authorizationPending,
				authorizationPending,
				authorizationPending,
			})
			defer ms.Close()

			timeNow := newStubTimeNow(interval)
			timeSleep := newMockTimeSleep()
			daf, _ := auth.NewDeviceAuthFlow(
				auth.WithBaseURL(ms.URL),
				auth.WithClientID(clientID),
				auth.WithTimeNow(timeNow),
				auth.WithTimeSleep(timeSleep.f),
			)

			// Act
			_, err := daf.PollToken(dc)

			// Assert
			Expect(err).To(MatchError(&auth.ExpiredError{
				ExpiresIn: expiresIn,
			}))
			Expect(ms.restExpects()).To(BeEmpty())
			Expect(timeSleep.calls).To(Equal([]time.Duration{intervalD, intervalD, intervalD, intervalD}))
		})

		It("returns APIError when api error excepts authorization pending occurred", func() {
			// Arrange
			statusCode := 403
			errorCode := "unauthorized_client"
			errorDescription := "Unauthorized or unknown client"
			ms := newMockServer([]requestExpectation{
				{
					path:       apiPath,
					form:       expectedForm,
					statusCode: statusCode,
					responseBody: fmt.Sprintf(`{
						"error": "%s",
						"error_description": "%s"
					}`, errorCode, errorDescription),
				},
			})
			defer ms.Close()

			timeNow := newStubTimeNow(interval)
			timeSleep := newMockTimeSleep()
			daf, _ := auth.NewDeviceAuthFlow(
				auth.WithBaseURL(ms.URL),
				auth.WithClientID(clientID),
				auth.WithTimeNow(timeNow),
				auth.WithTimeSleep(timeSleep.f),
			)

			// Act
			_, err := daf.PollToken(dc)

			// Assert
			Expect(err).To(MatchError(&auth.APIError{
				StatusCode: statusCode,
				Body: &auth.ErrorResponse{
					Error:            errorCode,
					ErrorDescription: errorDescription,
				},
			}))
			Expect(ms.restExpects()).To(BeEmpty())
			Expect(timeSleep.calls).To(BeEmpty())
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

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer GinkgoRecover()
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

var baseStubTime time.Time

func newStubTimeNow(stepSec int) func() time.Time {
	t := baseStubTime
	return func() time.Time {
		ret := t
		t = t.Add(time.Duration(stepSec) * time.Second)
		return ret
	}
}

func newMockTimeSleep() *struct {
	calls []time.Duration
	f     func(time.Duration)
} {
	calls := make([]time.Duration, 0)
	mock := &struct {
		calls []time.Duration
		f     func(time.Duration)
	}{
		calls: calls,
	}

	mock.f = func(d time.Duration) {
		mock.calls = append(mock.calls, d)
	}

	return mock
}

func init() {
	baseStubTime, _ = time.Parse(time.RFC3339, "2022-08-29T10:00:00Z")
}
