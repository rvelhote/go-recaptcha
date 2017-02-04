// Package recaptcha allows you to intereact with the Google reCAPTCHA API to verify users.
// The MIT License (MIT)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package recaptcha

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"
)

// siteVerifyURL is The URL that's used to verify the user's response to the challenge.
// @see https://developers.google.com/recaptcha/docs/verify#api-request
const siteVerifyURL = "https://www.google.com/recaptcha/api/siteverify"

// RecaptchaErrorMap is the list of error codes mapped to a human-readable error code.
// @see https://developers.google.com/recaptcha/docs/verify#error-code-reference
var RecaptchaErrorMap = map[string]string{
	"missing-input-secret":   "The secret parameter is missing.",
	"invalid-input-secret":   "The secret parameter is invalid or malformed.",
	"missing-input-response": "The response parameter is missing.",
	"invalid-input-response": "The response parameter is invalid or malformed.",
}

// Response is the JSON structure that is returned by the verification API after a challenge response is verified.
// @see https://developers.google.com/recaptcha/docs/verify#api-response
type Response struct {
	Success    bool     `json:"success"`
	Challenge  string   `json:"challenge_ts"`
	Hostname   string   `json:"hostname"`
	ErrorCodes []string `json:"error-codes"`
}

// The Recaptcha main structure. Its only purpose is to verify the user's response to a challenge with Google.
// You should initialize the structure with the Private Key that was supplied to you in the documentation.
type Recaptcha struct {
	PrivateKey string
}

// Verify the users's response to the reCAPTCHA challege with the API server.
//
// The parameter response is obtained after the user successfully solves the challenge presented by the JS widget. The
// remoteip parameter is optional; just send it empty if you don't want to use it.
//
// This function will return a boolean that will have the final result returned by the API as well as an optional list
// of errors. They might be useful for logging purposed but you don't have to show them to the user.
func (r Recaptcha) Verify(response string, remoteip string) (bool, []error) {
	params := url.Values{}

	if len(r.PrivateKey) > 0 {
		params.Set("secret", r.PrivateKey)
	}

	if len(response) > 0 {
		params.Set("response", response)
	}

	if net.ParseIP(remoteip) != nil {
		params.Set("remoteip", remoteip)
	}

	jsonResponse := Response{}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	httpResponse, _ := httpClient.PostForm(siteVerifyURL, params)

    defer httpResponse.Body.Close()

	bufferedReader := bufio.NewReader(httpResponse.Body)
	json.NewDecoder(bufferedReader).Decode(&jsonResponse)

	apiErrors := make([]error, len(jsonResponse.ErrorCodes))
	for i, singleError := range jsonResponse.ErrorCodes {
		apiErrors[i] = errors.New(RecaptchaErrorMap[singleError])
	}

	return jsonResponse.Success, apiErrors
}
