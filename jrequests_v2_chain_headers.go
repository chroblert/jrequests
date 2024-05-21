package jrequests

import (
	"golang.org/x/net/http2"
	"net/http"
	"net/url"
)

// 用于链式
type Jrequest struct {
	Headers map[string][]string
	Params  map[string][]string
	Cookies []*http.Cookie

	Proxy        *url.URL // string //func(*http.Request) (*url.URL, error)
	Timeout      int
	Data         []byte
	IsRedirect   bool
	IsVerifySSL  bool
	HttpVersion  int
	IsKeepAlive  bool
	BSendRST     bool
	IsKeepCookie bool
	CAPath       string
	Url          string
	transport    *http.Transport
	transport2   *http2.Transport
	cli          *http.Client
	req          *http.Request
	method       string
	err          error
}

type Jresponse struct {
	Resp *http.Response
}
