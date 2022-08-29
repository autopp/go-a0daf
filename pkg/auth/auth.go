// Copyright (C) 2022	 Akira Tanimura (@autopp)
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an “AS IS” BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"time"
)

type DeviceAuthFlow struct {
	baseURL   string
	clientID  string
	timeNow   func() time.Time
	timeSleep func(d time.Duration)
}

type DeviceCodeResponse struct {
	DeviceCode              string    `json:"device_code"`
	UserCode                string    `json:"user_code"`
	VerificationURI         string    `json:"verification_uri"`
	VerificationURIComplete string    `json:"verification_uri_complete"`
	ExpiresIn               int       `json:"expires_in"`
	Interval                int       `json:"interval"`
	ExpiresAt               time.Time `json:"-"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type APIError struct {
	StatusCode int
	Body       *ErrorResponse
}

func (e *APIError) Error() string {
	return e.Body.Error + ": " + e.Body.ErrorDescription
}

type ExpiredError struct {
	ExpiresIn int
}

func (e *ExpiredError) Error() string {
	return fmt.Sprintf("authorization was expired in %d sec", e.ExpiresIn)
}

type DeviceAuthFlowOption interface {
	apply(daf *DeviceAuthFlow) error
}

func NewDeviceAuthFlow(opts ...DeviceAuthFlowOption) (*DeviceAuthFlow, error) {
	daf := &DeviceAuthFlow{
		timeNow:   time.Now,
		timeSleep: time.Sleep,
	}

	// apply options
	for _, opt := range opts {
		if err := opt.apply(daf); err != nil {
			return nil, err
		}
	}

	// complete instance
	if daf.baseURL == "" {
		return nil, errors.New("BaseURL is not given, use WithBaseURL()")
	}

	if daf.clientID == "" {
		return nil, errors.New("ClientID is not given, use WithClientID()")
	}

	return daf, nil
}

type WithBaseURL string

func (baseURL WithBaseURL) apply(daf *DeviceAuthFlow) error {
	daf.baseURL = string(baseURL)
	return nil
}

type WithClientID string

func (clientID WithClientID) apply(daf *DeviceAuthFlow) error {
	daf.clientID = string(clientID)
	return nil
}

type WithTimeNow func() time.Time

func (timeNow WithTimeNow) apply(daf *DeviceAuthFlow) error {
	daf.timeNow = timeNow
	return nil
}

type WithTimeSleep func(d time.Duration)

func (timeSleep WithTimeSleep) apply(daf *DeviceAuthFlow) error {
	daf.timeSleep = timeSleep
	return nil
}

func (daf *DeviceAuthFlow) BaseURL() string {
	return daf.baseURL
}

func (daf *DeviceAuthFlow) ClientID() string {
	return daf.clientID
}

func (daf *DeviceAuthFlow) FetchDeviceCode(scope string, audience string) (*DeviceCodeResponse, error) {
	url := daf.baseURL + "/oauth/device/code"
	payload := strings.NewReader(fmt.Sprintf("client_id=%s&scope=%s&audience=%s", daf.clientID, neturl.QueryEscape(scope), neturl.QueryEscape(audience)))

	statusCode, resBody, err := postForm(url, payload)
	now := daf.timeNow()
	if err != nil {
		return nil, err
	}

	if statusCode != 200 {
		if statusCode/100 == 4 {
			er := new(ErrorResponse)
			if err := json.Unmarshal(resBody, er); err != nil {
				return nil, fmt.Errorf("could not decode device code response body: %w", err)
			}
			return nil, &APIError{StatusCode: statusCode, Body: er}
		}
		return nil, fmt.Errorf("device code request was failed: %s", string(resBody))
	}

	dc := new(DeviceCodeResponse)
	if err := json.Unmarshal(resBody, dc); err != nil {
		return nil, fmt.Errorf("could not decode device code response body: %w", err)
	}

	dc.ExpiresAt = now.Add(time.Duration(dc.ExpiresIn) * time.Second)

	return dc, nil
}

func (daf *DeviceAuthFlow) PollToken(dc *DeviceCodeResponse) (*TokenResponse, error) {
	interval := time.Duration(dc.Interval) * time.Second
	url := daf.baseURL + "/oauth/token"
	payload := fmt.Sprintf("grant_type=%s&device_code=%s&client_id=%s", "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code", dc.DeviceCode, daf.clientID)

	for {
		if !daf.timeNow().Before(dc.ExpiresAt) {
			return nil, &ExpiredError{
				ExpiresIn: dc.ExpiresIn,
			}
		}

		statusCode, resBody, err := postForm(url, strings.NewReader(payload))

		if statusCode == 200 {
			t := new(TokenResponse)
			if err = json.Unmarshal(resBody, t); err != nil {
				return nil, fmt.Errorf("could not decode token response body: %w", err)
			}
			return t, nil
		}

		if statusCode/100 != 4 {
			return nil, fmt.Errorf("token request was failed: %s", string(resBody))
		}

		er := new(ErrorResponse)
		if err = json.Unmarshal(resBody, er); err != nil {
			return nil, fmt.Errorf("could not decode token response body: %w", err)
		}

		if er.Error != "authorization_pending" {
			return nil, &APIError{StatusCode: statusCode, Body: er}
		}

		daf.timeSleep(interval)
	}
}

func postForm(url string, payload io.Reader) (int, []byte, error) {
	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return 0, nil, fmt.Errorf("could not create request: %w", err)
	}
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("request was failed: %w", err)
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("could not read response body: %w", err)
	}

	return res.StatusCode, resBody, nil
}
