package jrequests

import (
	"golang.org/x/net/http2"
	"net/http"
	"sync"
)

var jrePool = &sync.Pool{New: func() interface{} {
	return &Jrequest{
		Proxy:   nil,
		Timeout: 60,
		Headers: map[string][]string{
			"User-Agent": {"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0"},
		},
		Data:         nil,
		Params:       nil,
		Cookies:      nil,
		IsRedirect:   true,
		IsVerifySSL:  false,
		HttpVersion:  1,
		IsKeepAlive:  false,
		BSendRST:     false,
		IsKeepCookie: false,
		CAPath:       "cas",
		//Url:         "",
		transport:  &http.Transport{},
		transport2: &http2.Transport{},
		cli:        &http.Client{},
	}
}}

func resetJr(jre interface{}) {
	// TODO 如何将Jnrequest转为Jrequest
	jr := jre.(*Jrequest)
	jr.Proxy = nil
	jr.Timeout = 60
	jr.Headers = map[string][]string{
		"User-Agent": {"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0"},
	}
	jr.Data = nil
	jr.Params = nil
	jr.Cookies = nil
	jr.IsRedirect = true
	jr.IsVerifySSL = false
	jr.HttpVersion = 1
	jr.IsKeepAlive = false
	jr.BSendRST = false
	jr.CAPath = "cas"
	jr.transport = &http.Transport{}
	jr.transport2 = &http2.Transport{}
	jr.cli = &http.Client{}
}
