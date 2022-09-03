# go-a0daf

The CLI and library for [the device authorization flow of Auth0](https://auth0.com/docs/get-started/authentication-and-authorization-flow/call-your-api-using-the-device-authorization-flow).

The CLI shows user code and verification URL. After verification, it shows the response from [token endpoint](https://auth0.com/docs/api/authentication#device-authorization-flow48).

## Install

For CLI, download binary from [release page](https://github.com/autopp/go-a0daf/releases) or use `go install`.

```
$ go install github.com/autopp/go-a0daf/cmd/a0daf
```

## Usage of CLI

`a0daf` receives configurations from enviroment variables.

| Variable | Example |
| --- | -- |
| `A0DAF_BASE_URL` | `https://example.us.auth0.com` |
| `A0DAF_CLIENT_ID` | - |
| `A0DAF_SCOPE` | `openid profile` |
| `A0DAF_AUDIENCE` | `"https://example.com/your/api"` |

```
$ a0daf
Code: ABCD-EFGH
Access: https://example.us.auth0.com/activate

(Access the URL and verify)

{"access_token":"eyJz93a...k4laUWw","refresh_token":"eyJ...MoQ","id_token":"eyJ...0NE","token_type":"Bearer","expires_in":86400}
```

## Usage of library

Use `*DeviceFlowAuth`'s method `FetchDeviceCode` and `PollToken` in `github.com/autopp/go-a0daf/pkg/auth`.

```go
package main

import "github.com/autopp/go-a0daf/pkg/auth"

func main() {
  // Create a client instance
  daf, _ := auth.NewDeviceAuthFlow(
    auth.WithBaseURL("https://example.us.auth0.com"),
    auth.WithClientID("xxxx")
  )

  // Get device code
  dc, _ := daf.FetchDeviceCode("openid profile", "https://example.com/your/api")

  // Show dc.UserCode and dc.VerificationURI or dc.VerificationURIComplete

  // Poll token
  token, err := daf.PollToken(dc)
  var expiredError *auth.ExpiredError
  if err != nil {
    if errors.As(err, &expiredError) {
      // verification was expired
    } else {
      // other error was occured
    }
  } else {
    // Ok, now we get token!
  }
}
```

## License

[Apache License 2.0](LICENSE)
