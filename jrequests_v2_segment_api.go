package jrequests

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/chroblert/jrequests/jfile"
	"golang.org/x/net/http2"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// 用于新建
//type Jnrequest struct {
//	Headers map[string][]string
//	Params  map[string][]string
//	Cookies []*http.Cookie
//
//	Proxy        *url.URL //string //func(*http.Request) (*url.URL, error)
//	Timeout      int
//	Data         []byte
//	IsRedirect   bool
//	IsVerifySSL  bool
//	HttpVersion  int
//	IsKeepAlive  bool
//	BSendRST     bool
//	IsKeepCookie bool
//	CAPath       string
//	Url          string
//	transport    *http.Transport
//	transport2   *http2.Transport
//	cli          *http.Client
//	req          *http.Request
//	method       string
//}

type Jnrequest Jrequest

// 创建实例
// param d:是否保存cookie，true or false
func New(d ...interface{}) (jrn *Jnrequest, err error) {
	jrn = (*Jnrequest)(jrePool.Get().(*Jrequest))
	jrn.cli.Jar, err = cookiejar.New(nil)
	if err != nil {
		return
	}
	// 设置是否保存cookie
	if len(d) > 0 {
		switch d[0].(type) {
		case bool:
			jrn.IsKeepCookie = d[0].(bool)
		default:
			jrn.IsKeepCookie = false
		}
	}
	return
}

func (jr *Jnrequest) Request(reqMethod, reqUrl string, d ...interface{}) (resp *Jresponse, err error) {
	resp = &Jresponse{}
	//jr.Url = reqUrl
	var reader io.Reader
	if len(d) > 0 {
		switch d[0].(type) {
		case []byte:
			reader = bytes.NewReader(d[0].([]byte))
		case string:
			reader = strings.NewReader(d[0].(string))
		default:
			reader = nil
		}
	} else {
		reader = nil
	}

	//req2, err = http.NewRequest("GET", reqUrl, reader)
	req2, err := http.NewRequest(reqMethod, reqUrl, reader)
	if err != nil {
		return nil, err
	}
	// 设置headers
	for k, v := range jr.Headers {
		for _, v2 := range v {
			req2.Header.Add(k, v2)
		}
	}
	// 设置cookies
	//u, err := url.Parse(reqUrl)
	//jr.cli.Jar.SetCookies(u, jr.Cookies)
	// 设置是否转发
	if !jr.IsRedirect {
		jr.cli.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			// 对302的location地址，不follow
			return http.ErrUseLastResponse
		}
	}
	// 设置params
	if jr.Params != nil {
		query := req2.URL.Query()
		for paramKey, paramValue := range jr.Params {
			//query.Add(paramKey, paramValue)
			for _, v2 := range paramValue {
				query.Add(paramKey, v2)
			}
		}
		req2.URL.RawQuery = query.Encode()
	}
	// 设置代理
	if jr.Proxy != nil {
		jr.transport.Proxy = func(request *http.Request) (*url.URL, error) {
			return jr.Proxy, nil
		}
	} else {
		jr.transport.Proxy = nil
	}
	// 设置超时
	jr.cli.Timeout = time.Second * time.Duration(jr.Timeout)

	// 设置是否验证服务端证书
	if !jr.IsVerifySSL {
		if jr.transport.TLSClientConfig != nil {
			jr.transport.TLSClientConfig.InsecureSkipVerify = true
		} else {
			jr.transport.TLSClientConfig = &tls.Config{
				InsecureSkipVerify: true, // 遇到不安全的https跳过验证
			}
		}

	} else {
		var rootCAPool *x509.CertPool
		rootCAPool, err := x509.SystemCertPool()
		if err != nil {
			rootCAPool = x509.NewCertPool()
		}
		// 判断当前程序运行的目录下是否有cas目录
		// 根证书，用来验证服务端证书的ca
		if isExsit, _ := jfile.PathExists(jr.CAPath); isExsit {
			// 枚举当前目录下的文件
			caFilenames, _ := jfile.GetFilenamesByDir(jr.CAPath)
			if len(caFilenames) > 0 {
				for _, filename := range caFilenames {
					caCrt, err := ioutil.ReadFile(filename)
					if err != nil {
						return nil, err
					}
					//jlog.Debug("导入证书结果:", rootCAPool.AppendCertsFromPEM(caCrt))
					rootCAPool.AppendCertsFromPEM(caCrt)
				}
			}
		}
		if jr.transport.TLSClientConfig != nil {
			jr.transport.TLSClientConfig.RootCAs = rootCAPool
		} else {
			jr.transport.TLSClientConfig = &tls.Config{
				RootCAs: rootCAPool,
			}
		}
		jr.transport.TLSClientConfig = &tls.Config{
			RootCAs: rootCAPool,
		}
	}
	// 设置transport
	// TODO 做个备份 没起作用??? new一次，只能为 http/1.1或http/2
	backTransport := jr.transport
	//tmp := *jr.transport
	//backTransport := &tmp
	if jr.HttpVersion == 2 {
		// 判断当前是否已经为http2
		alreadyH2 := false
		if jr.transport.TLSClientConfig != nil {
			for _, v := range jr.transport.TLSClientConfig.NextProtos {
				if v == "h2" {
					alreadyH2 = true
					break
				}
			}
		}
		if !alreadyH2 {
			err = http2.ConfigureTransport(backTransport)
			if err != nil {
				return nil, err
			}
		}
	}
	jr.cli.Transport = backTransport
	// 设置connection
	req2.Close = !jr.IsKeepAlive
	resp.Resp, err = jr.cli.Do(req2)
	// 清空cookie
	if err == nil {
		// 清空cookie
		if !jr.IsKeepCookie {
			jr.cli.Jar, err = cookiejar.New(nil)
		}
	}
	return
}

// TODO 解决并发 资源共享问题
func (jr *Jnrequest) Get(reqUrl string, d ...interface{}) (resp *Jresponse, err error) {
	return jr.Request("GET", reqUrl, d)
}
func (jr *Jnrequest) POST(reqUrl string, d ...interface{}) (resp *Jresponse, err error) {
	return jr.Request("POST", reqUrl, d)
}
func (jr *Jnrequest) PUT(reqUrl string, d ...interface{}) (resp *Jresponse, err error) {
	return jr.Request("PUT", reqUrl, d)
}
func (jr *Jnrequest) HEAD(reqUrl string, d ...interface{}) (resp *Jresponse, err error) {
	return jr.Request("HEAD", reqUrl, d)
}
func (jr *Jnrequest) DELETE(reqUrl string, d ...interface{}) (resp *Jresponse, err error) {
	return jr.Request("DELETE", reqUrl, d)
}

// 设置代理
func (jr *Jnrequest) SetProxy(proxy string) {
	if jr == nil {
		return
	}
	if strings.TrimSpace(proxy) == "" {
		// 若为空，直接返回jr
		return
	}
	// TODO proxy格式校验
	pUrl, err := url.Parse(proxy)
	if err != nil {
		return
	}
	jr.Proxy = pUrl
}

// 设置超时
func (jr *Jnrequest) SetTimeout(timeout int) {
	if jr == nil {
		return
	}
	jr.Timeout = timeout
	//jr.cli.Timeout = time.Second * time.Duration(jr.Timeout)
}

// 重置并设置headers
func (jr *Jnrequest) SetHeaders(headers map[string][]string) {
	if jr == nil {
		return
	}
	if len(headers) == 0 {
		jr.Headers = make(map[string][]string)
		return
	} else {
		jr.Headers = make(map[string][]string, len(headers))
	}
	for k, v := range headers {
		jr.Headers[k] = make([]string, len(v))
		for k2, v2 := range v {
			jr.Headers[k][k2] = v2
		}
	}
}

// 添加headers
func (jr *Jnrequest) AddHeaders(headers map[string]string) {
	if jr == nil {
		return
	}
	if jr.Headers == nil {
		if len(headers) == 0 {
			jr.Headers = make(map[string][]string)
			return
		} else {
			jr.Headers = make(map[string][]string, len(headers))
		}
	}
	for k, v := range headers {
		if _, ok := jr.Headers[k]; !ok {
			jr.Headers[k] = []string{v}
		} else {
			jr.Headers[k] = append(jr.Headers[k], v)
		}
	}
}

// 设置body data
func (jr *Jnrequest) SetData(d interface{}) {
	if jr == nil {
		return
	}
	switch d.(type) {
	case []byte:
		jr.Data = d.([]byte)
	case string:
		jr.Data = []byte(d.(string))
	default:
		jr.Data = []byte(nil)
	}
	//jr.Data = data
}

// 设置params
func (jr *Jnrequest) SetParams(params map[string][]string) {
	if jr == nil {
		return
	}
	if len(params) == 0 {
		jr.Params = make(map[string][]string)
		return
	} else {
		jr.Params = make(map[string][]string, len(params))
	}
	for k, v := range params {
		jr.Params[k] = make([]string, len(v))
		for k2, v2 := range v {
			jr.Params[k][k2] = v2
		}
	}
}

// 追加params,1
func (jr *Jnrequest) AddParams(params map[string]string) {
	if jr == nil {
		return
	}
	if jr.Params == nil {
		if len(params) == 0 {
			jr.Params = make(map[string][]string)
			return
		} else {
			jr.Params = make(map[string][]string, len(params))
		}
	}
	//jr.Params = params
	for k, v := range params {
		if _, ok := jr.Params[k]; !ok {
			jr.Params[k] = []string{v}
		} else {
			jr.Params[k] = append(jr.Params[k], v)
		}
	}
	return
}

// 设置cookies
func (jr *Jnrequest) SetCookies(cookies map[string]string) {
	if jr == nil {
		return
	}
	if jr.Cookies == nil {
		jr.Cookies = make([]*http.Cookie, len(cookies))
	}
	if jr.Headers == nil {
		jr.Headers = make(map[string][]string)
	}
	cookieStrList := []string{}
	for kName, kVal := range cookies {
		tmpCookieStr := fmt.Sprintf("%s=%s", kName, kVal)
		cookieStrList = append(cookieStrList, tmpCookieStr)
	}
	jr.Headers["Cookie"] = cookieStrList
}

// 添加cookies
func (jr *Jnrequest) AddCookies(cookies map[string]string) {
	if jr == nil {
		return
	}
	if jr.Cookies == nil {
		jr.Cookies = make([]*http.Cookie, len(cookies))
	}
	bNoCookie := true

	// headers中有cookie
	if jr.Headers == nil {
		jr.Headers = make(map[string][]string)
	} else {
		for k, _ := range jr.Headers {
			if k == "Cookie" {
				bNoCookie = false
				break
			}
		}
	}
	cookieStrList := []string{}
	for kName, kVal := range cookies {
		tmpCookieStr := fmt.Sprintf("%s=%s", kName, kVal)
		cookieStrList = append(cookieStrList, tmpCookieStr)
	}
	if bNoCookie {
		jr.Headers["Cookie"] = cookieStrList
	} else {
		jr.Headers["Cookie"] = append(jr.Headers["Cookie"], cookieStrList...)
	}

	return
}

// 设置是否转发
func (jr *Jnrequest) SetIsRedirect(isredirect bool) {
	if jr == nil {
		return
	}
	jr.IsRedirect = isredirect
}

// 设置http 2.0
func (jr *Jnrequest) SetHttpVersion(version int) {
	if jr == nil {
		return
	}
	jr.HttpVersion = version
}

// 设置是否验证ssl
func (jr *Jnrequest) SetIsVerifySSL(isverifyssl bool) {
	if jr == nil {
		return
	}
	jr.IsVerifySSL = isverifyssl
}

// 设置connection是否为长连接，keep-alive
func (jr *Jnrequest) SetKeepalive(iskeepalive bool) {
	if jr == nil {
		return
	}
	jr.IsKeepAlive = iskeepalive
}

// 设置发包后，是否发送RST包，用于缓解TIME_WAIT问题
func (jr *Jnrequest) SetRST(bSendRST bool) {
	if jr == nil {
		return
	}
	jr.BSendRST = bSendRST
}

// 设置capath
func (jr *Jnrequest) SetCAPath(CAPath string) {
	if jr == nil {
		return
	}
	jr.CAPath = CAPath
}
