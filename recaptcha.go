/*
 * The MIT License (MIT)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package recaptcha

import (
    "net/http"
    "net/url"
    "net"
    "time"
    "bufio"
    "encoding/json"
    "errors"
)

const VerifyUrl = "https://www.google.com/recaptcha/api/siteverify"

var RecaptchaErrorMap = map[string] string {
"missing-input-secret": "The secret parameter is missing.",
"invalid-input-secret": "The secret parameter is invalid or malformed.",
"missing-input-response": "The response parameter is missing.",
"invalid-input-response": "The response parameter is invalid or malformed.",
}

type RecaptchaResponse struct {
	success bool `json:"success"`
	challenge string `json:"challenge_ts"`
	hostname string `json:"hostname"`
	errorCodes []string `json:"error-codes"`
}

type Recaptcha struct {
    PrivateKey string
}

func (r Recaptcha) Verify(response string, remoteip string) (bool, []error) {
    params := url.Values{}
    params.Set("secret", r.PrivateKey)
    params.Set("response", response)

    if net.ParseIP(remoteip) != nil {
        params.Set("remoteip", remoteip)
    }

    jsonResponse := RecaptchaResponse{}

    httpClient := &http.Client{ Timeout: 10 * time.Second }
    httpResponse, _ := httpClient.PostForm(VerifyUrl, params)

    bufferedReader := bufio.NewReader(httpResponse.Body)
    json.NewDecoder(bufferedReader).Decode(&jsonResponse)

    apiErrors := make([]error, len(jsonResponse.errorCodes))
    for i, singleError := range jsonResponse.errorCodes {
        apiErrors[i] = errors.New(RecaptchaErrorMap[singleError])
    }

    return jsonResponse.success, apiErrors
}
