// Package recaptcha allows you to interact with the Google reCAPTCHA API to verify user responses to the challenge.
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
	"testing"
)

const TestPrivateKey = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"
const TestResponse = "03AHJ_VutING-ky641XG-W15BMWlC31rMqgdxuAFji7Pqk1o6jqBF20CfKSTknHDlXLQlVgleevn5HTHsldBinf78xGvNYAX-gIXSzOX7aQBBTvNAY7o4SlLzUzEEC3AXNTqxz76ueA4bx2-0BHN5gfTG2vUBpktWKa7BOsJLPgAS9b2IidWB41UUccQl7pEs9H28qUKXGYRnKZFECk23jcjqMPkvDVTFASctPXC3a40YtiYB2bzY7LfqDeaqYH0_nJf0BcY_SZfhQJetE6KPhL9bocIOgcWRoZQ8b0eXKHClMfbHRTCfu10k0Eu1gzx3T992KoQ643C_YPPj2VasIDiNx1FEX_5Yvs2jzSYjRy2jyAtVtNEUSKhFoEd3pwGJJtx7eh6FbYcbAWZKZTuWejmGzpAQaB6fMuD5ykY1AIFYiYjFFXjks_K3ZICH4pmU6WFUDUDVUxiT28-OVWCtYr7X_s0Ce9fQ6L9tZINVaaZeqazzuxfeNxYI66PEV2nMVUjcBTwrLdVtaWjoH9S3Cpc9xoXZZe3dtfXkw2nyhK6CFehEoKOBi96HepA5cY1YWUbAeJMIYoEp-lla6OmENGhrkLN28mUHF-iH68fe2LxwkhCGMic09GVOOXE5TUFhspvIHfgoOBE4-s1j4AWezUP2hniuJClPsO6xxiAQgIqA2dy0_NNKLI3Cyb3dTIFd8yv26U7kSJUGxmjI4BHlRxoNXniBuf854UX820VpIFr-oXkJj0GoqBAcrlgucq8PsjuPOCdHoh8u2zTYFitxppqDR1NP4wzdVoKuZ-BVhQkJ1C3IsfrAkLyesFfF5y8KQFo1smzhMnHmEiMLRDWe9y9hhd3CpkNdofvedcaE6PJ_l-dH8hdmhS_PgSaZPHGM3Wym2U3xICD2Yde1BWp1Imik6eM43OkYJfP6sh_IdX38cWi74B3RfCA_Na1Tci3_24cuEs8IfBHeQnxgN7V5FGL204ZLFffeGIxmXlbInAeZgFEqJw3YjQfu4lbddYXTKOE6WJZcKmRSjXazt8ZXaxKJ_0SefI7udyg"
const TestRemoteIP = "127.0.0.1"

// This test will use the reCAPTCHA test private and site keys to make a successful request to the verification API.
// These keys can be found at https://developers.google.com/recaptcha/docs/faq
func TestRecaptcha_Verify(t *testing.T) {
	recaptcha := Recaptcha{PrivateKey: TestPrivateKey}
    response, errors := recaptcha.Verify(TestResponse, TestRemoteIP)

	if response.Success != true {
		t.Error("The test should have succeeded because the test data always succeeds.")
	}

	if len(errors) != 0 {
		t.Errorf("There should be no errors but there were -- %d -- errors!", len(errors))
	}
}

// This test will send an empty challenge value. The API should reply with the correct error message.
func TestRecaptcha_VerifyEmptyResponseParameter(t *testing.T) {
	recaptcha := Recaptcha{PrivateKey: TestPrivateKey}
    response, errors := recaptcha.Verify("", TestRemoteIP)

	if response.Success != false {
		t.Error("The API response for this test should have been a failure!")
	}

	if len(errors) != 1 {
		t.Error("Should only have a single error!")
	}

	if len(errors) == 1 && errors[0] != RecaptchaErrorMap["missing-input-response"] {
		t.Errorf("The error should have been -- %s -- and it was -- %s --", RecaptchaErrorMap["missing-input-response"], errors[0])
	}
}

// This test will send an invalid/malformed challenge value. The API should reply with the correct error message.
func TestRecaptcha_VerifyMalformedResponseParameter(t *testing.T) {
	recaptcha := Recaptcha{PrivateKey: TestPrivateKey}
    response, errors := recaptcha.Verify("This is a MALFORMED KEY", TestRemoteIP)

	if response.Success != false {
		t.Error("The API response for this test should have been a failure!")
	}

	if len(errors) != 1 {
		t.Error("Should only have a single error!")
	}

	if len(errors) == 1 && errors[0] != RecaptchaErrorMap["invalid-input-response"] {
		t.Errorf("The error should have been -- %s -- and it was -- %s --", RecaptchaErrorMap["invalid-input-response"].Error(), errors[0].Error())
	}
}

// This test will send an empty private key value. The API should reply with the correct error message.
func TestRecaptcha_VerifyInvalidSecretParameter(t *testing.T) {
	recaptcha := Recaptcha{PrivateKey: ""}
	response, errors := recaptcha.Verify(TestResponse, TestRemoteIP)

	if response.Success != false {
		t.Error("The API response for this test should have been a failure!")
	}

	if len(errors) != 1 {
		t.Error("Should only have a single error!")
	}

	if len(errors) == 1 && errors[0] != RecaptchaErrorMap["missing-input-secret"] {
		t.Errorf("The error should have been -- %s -- and it was -- %s --", RecaptchaErrorMap["missing-input-secret"].Error(), errors[0].Error())
	}
}

// This test will send a malformed private key value. The API should reply with the correct error message.
func TestRecaptcha_VerifyMalformedSecretParameter(t *testing.T) {
	recaptcha := Recaptcha{PrivateKey: "This is a MALFORMED PRIVATE KEY"}
    response, errors := recaptcha.Verify(TestResponse, TestRemoteIP)

	if response.Success != false {
		t.Error("The API response for this test should have been a failure!")
	}

	if len(errors) != 1 {
		t.Error("Should only have a single error!")
	}

	if len(errors) == 1 && errors[0] != RecaptchaErrorMap["invalid-input-secret"] {
		t.Errorf("The error should have been -- %s -- and it was -- %s --", RecaptchaErrorMap["invalid-input-secret"].Error(), errors[0])
	}
}

func TestRecaptcha_VerifyMultipleErrors(t *testing.T) {
	recaptcha := Recaptcha{PrivateKey: "This is a MALFORMED PRIVATE KEY"}
    response, errors := recaptcha.Verify("This is a MALFORMED RESPONSE", TestRemoteIP)

	if response.Success != false {
		t.Error("The API response for this test should have been a failure!")
	}

	if len(errors) != 2 {
		t.Error("There should be exactly two errors!")
	}

	if len(errors) == 2 {
		if errors[0] != RecaptchaErrorMap["invalid-input-response"] {
			t.Errorf("The first error should have been -- %s -- and it was -- %s --", RecaptchaErrorMap["invalid-input-response"], errors[0])
		}
		if errors[1] != RecaptchaErrorMap["invalid-input-secret"] {
			t.Errorf("The second error should have been -- %s -- and it was -- %s --", RecaptchaErrorMap["invalid-input-secret"], errors[1])
		}
	}
}

func TestRecaptcha_VerifyHttpStatusError(t *testing.T) {
	recaptcha := Recaptcha{URL: "https://www.google.com/recaptcha/api/siteverify-404404"}
    response, errors := recaptcha.Verify("", "")

	if response.Success != false {
		t.Error("The verification response for this test should have been a failure!")
	}

	if len(errors) != 1 {
		t.Errorf("The verification function should have returned one error. It returned %d. With the content -- %s", len(errors), errors)
	}
}

func TestRecaptcha_VerifyHttpError(t *testing.T) {
	recaptcha := Recaptcha{URL: "https://this-domain-does-not-exist-www.google.com/recaptcha/api/siteverify"}
    response, errors := recaptcha.Verify("", "")

	if response.Success != false {
		t.Error("The verification response for this test should have been a failure!")
	}

	if len(errors) != 1 {
		t.Errorf("The verification function should have returned one error. It returned %d. With the content -- %s", len(errors), errors)
	}
}
