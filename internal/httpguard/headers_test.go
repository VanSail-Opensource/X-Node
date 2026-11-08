package httpguard

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
)

func TestAllowedOriginChangeStripsCredentialsAfterCallbackAndCookieJar(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	cdn, err := url.Parse(cdnURL)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(cdn, []*http.Cookie{{Name: "cdn-session", Value: "jar-secret", Secure: true}})
	if len(jar.Cookies(cdn)) != 1 {
		t.Fatal("cookie fixture was not installed")
	}
	var received http.Header
	calls, callbacks := 0, 0
	transport := &mockTransport{fn: func(request *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return mockResponse(request, http.StatusFound, cdnURL), nil
		}
		received = request.Header.Clone()
		return mockResponse(request, http.StatusOK, ""), nil
	}}
	client := &http.Client{Transport: transport, Jar: jar, CheckRedirect: func(request *http.Request, _ []*http.Request) error {
		callbacks++
		request.Header.Set("Authorization", "Bearer callback-secret")
		request.Header.Set("X-API-Key", "callback-key")
		request.Header["cookie"] = []string{"callback=secret"}
		return nil
	}}
	request := requestForTest(t, http.MethodGet, releaseURL)
	for _, name := range []string{"Authorization", "Cookie", "Proxy-Authorization", "Referer", "Origin", "X-API-Key", "X-Custom-Secret"} {
		request.Header.Set(name, "original-secret")
	}
	request.Header["authorization"] = []string{"lowercase-secret"}
	request.Header.Set("User-Agent", "X-Node")
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("Range", "bytes=0-1023")
	response, err := Do(client, request, GitHubDownloads)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if calls != 2 || callbacks != 1 {
		t.Fatal("CDN boundary was not exercised")
	}
	if len(received) != 3 || received.Get("User-Agent") != "X-Node" || received.Get("Accept") != "application/octet-stream" || received.Get("Range") != "bytes=0-1023" {
		t.Fatal("unapproved headers crossed the origin boundary or safe headers disappeared")
	}
	if request.Header.Get("Authorization") != "original-secret" || request.Header.Get("Cookie") != "original-secret" || client.Transport != transport || client.Jar != jar || client.CheckRedirect == nil {
		t.Fatal("guard mutated the source request or injected client")
	}
}
