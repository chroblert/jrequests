package jrequests

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"github.com/chroblert/jrequests/jfile"
	"golang.org/x/net/http2"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"
)

func CGet(reqUrl string, d ...interface{}) (jre *jrequest) {
	var err error
	jre = jrePool.Get().(*jrequest)
	jre.cli.Jar, err = cookiejar.New(nil)
	if err != nil {
		return nil
	}
	jre.Url = reqUrl
	if len(d) > 0 {
		switch d[0].(type) {
		case []byte:
			jre.Data = d[0].([]byte)
		case string:
			jre.Data = []byte(d[0].(string))
		default:
			jre.Data = []byte(nil)
		}
	}
	jre.method = "GET"
	//// 设置transport
	//jre.cli.Transport = jre.transport
	return
}

func CPost(reqUrl string, d ...interface{}) (jre *jrequest) {
	var err error
	jre = jrePool.Get().(*jrequest)
	jre.cli.Jar, err = cookiejar.New(nil)
	if err != nil {
		return nil
	}
	jre.Url = reqUrl
	if len(d) > 0 {
		switch d[0].(type) {
		case []byte:
			jre.Data = d[0].([]byte)
		case string:
			jre.Data = []byte(d[0].(string))
		default:
			jre.Data = []byte(nil)
		}
	}
	jre.method = "POST"
	//// 设置transport
	//jre.cli.Transport = jre.transport
	return
}
func CPut(reqUrl string, d ...interface{}) (jre *jrequest) {
	var err error
	jre = jrePool.Get().(*jrequest)
	jre.cli.Jar, err = cookiejar.New(nil)
	if err != nil {
		return nil
	}
	jre.Url = reqUrl
	if len(d) > 0 {
		switch d[0].(type) {
		case []byte:
			jre.Data = d[0].([]byte)
		case string:
			jre.Data = []byte(d[0].(string))
		default:
			jre.Data = []byte(nil)
		}
	}
	jre.method = "PUT"
	//// 设置transport
	//jre.cli.Transport = jre.transport
	return
}

// 设置代理
// proxy: eg:http://ip:port
func (jr *jrequest) CSetProxy(proxy string) (jre *jrequest) {
	if jr == nil {
		return nil
	}
	// TODO proxy格式校验
	_, err := url.Parse(proxy)
	if err != nil {
		//jr.transport.Proxy = nil
		//jlog.Error(err)
		return nil
	}
	jr.Proxy = proxy
	if proxy != "" {
		jr.transport.Proxy = func(request *http.Request) (*url.URL, error) {
			return url.Parse(proxy)
		}
	} else {
		jr.transport.Proxy = nil
	}
	return jr
}

// 设置超时
func (jr *jrequest) CSetTimeout(timeout int) (jre *jrequest) {
	if jr == nil {
		return nil
	}
	jr.Timeout = timeout
	jr.cli.Timeout = time.Second * time.Duration(jr.Timeout)
	return jr
}

// 设置headers,1
func (jr *jrequest) CSetHeaders(headers map[string][]string) (jre *jrequest) {
	if jr == nil {
		return nil
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
	return jr
}

// 添加headers,1
func (jr *jrequest) CAddHeaders(headers map[string]string) (jre *jrequest) {
	if jr == nil {
		return nil
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
	return jr
}

// 设置body data,1
func (jr *jrequest) CSetData(d interface{}) (jre *jrequest) {
	if jr == nil {
		return nil
	}
	//jr.Data = d
	//var reader io.Reader
	switch d.(type) {
	case []byte:
		jr.Data = d.([]byte)
	case string:
		jr.Data = []byte(d.(string))
	default:
		jr.Data = []byte(nil)
	}
	//jr.req.Write()
	return jr
}

// 设置params,1
func (jr *jrequest) CSetParams(params map[string][]string) (jre *jrequest) {
	if jr == nil {
		return nil
	}
	if len(params) == 0 {
		jr.Params = make(map[string][]string)
		return jr
	} else {
		jr.Params = make(map[string][]string, len(params))
	}
	for k, v := range params {
		jr.Params[k] = make([]string, len(v))
		for k2, v2 := range v {
			jr.Params[k][k2] = v2
		}
	}
	return jr
}

// 追加params,1
func (jr *jrequest) CAddParams(params map[string]string) (jre *jrequest) {
	if jr == nil {
		return nil
	}
	if jr.Params == nil {
		if len(params) == 0 {
			jr.Params = make(map[string][]string)
			return jr
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
	return jr
}

// 设置cookies
func (jr *jrequest) CSetCookies(cookies []map[string]string) (jre *jrequest) {
	if jr == nil {
		return nil
	}
	if jr.Cookies == nil {
		jr.Cookies = make([]*http.Cookie, len(cookies))
	}
	for k, cookie := range cookies {
		for k2, v2 := range cookie {
			jr.Cookies[k] = &http.Cookie{Name: k2, Value: v2}
			break
		}
	}
	return jr
}

// 设置是否转发
func (jr *jrequest) CSetIsRedirect(isredirect bool) (jre *jrequest) {
	if jr == nil {
		return nil
	}
	jr.IsRedirect = isredirect
	// 设置是否转发
	if !jr.IsRedirect {
		jr.cli.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return jr
}

// 设置http 2.0
func (jr *jrequest) CSetHttpVersion(version int) (jre *jrequest) {
	if jr == nil {
		return nil
	}
	jr.HttpVersion = version
	// 设置httptransport
	switch jr.HttpVersion {
	case 1:
		//client.transport = httpTransport
	case 2:
		// 升级到http2
		//http2.ConfigureTransport(jr.transport)
		//tmpTransport,_ := http2.ConfigureTransports(jr.transport)
		//jr.transport = tmpTransport
		//client.transport = httpTransport
	}
	return jr
}

// 设置是否验证ssl
// 先设置capath
func (jr *jrequest) CSetIsVerifySSL(isverifyssl bool) (jre *jrequest) {
	if jr == nil {
		return nil
	}
	jr.IsVerifySSL = isverifyssl
	// 设置是否验证服务端证书
	if !jr.IsVerifySSL {
		jr.transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, // 遇到不安全的https跳过验证
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
						return nil
					}
					//jlog.Debug("导入证书结果:", rootCAPool.AppendCertsFromPEM(caCrt))
					rootCAPool.AppendCertsFromPEM(caCrt)
				}
			}
		}
		jr.transport.TLSClientConfig = &tls.Config{
			RootCAs: rootCAPool,
		}
	}
	return jr
}

// 设置connection是否为长连接，keep-alive
func (jr *jrequest) CSetKeepalive(iskeepalive bool) (jre *jrequest) {
	if jr == nil {
		return nil
	}
	jr.IsKeepAlive = iskeepalive
	return jr
}

// 设置capath
func (jr *jrequest) CSetCAPath(CAPath string) (jre *jrequest) {
	if jr == nil {
		return nil
	}
	jr.CAPath = CAPath
	return jr
}

// 发起请求
func (jre *jrequest) CDo() (resp *jresponse, err error) {
	var reader io.Reader = bytes.NewReader(jre.Data)
	//var err error
	jre.req, err = http.NewRequest(jre.method, jre.Url, reader)
	if err != nil {
		return nil, err
	}
	// 设置headers
	for k, v := range jre.Headers {
		for _, v2 := range v {
			jre.req.Header.Add(k, v2)
		}
	}
	// 设置params
	if jre.Params != nil {
		query := jre.req.URL.Query()
		for paramKey, paramValue := range jre.Params {
			//query.Add(paramKey, paramValue)
			for _, v2 := range paramValue {
				query.Add(paramKey, v2)
			}
		}
		jre.req.URL.RawQuery = query.Encode()
	}
	// 设置cookie
	u, err := url.Parse(jre.Url)
	jre.cli.Jar.SetCookies(u, jre.Cookies)
	// 设置是否转发
	if !jre.IsRedirect {
		jre.cli.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	// 设置connection
	jre.req.Close = !jre.IsKeepAlive
	// 设置短连接
	jre.transport.DisableKeepAlives = !jre.IsKeepAlive
	resp = &jresponse{}
	//jlog.Info(jre.req)
	// 设置transport
	backTransport := jre.transport
	//tmp := *jr.transport
	//backTransport := &tmp
	if jre.HttpVersion == 2 {
		// 判断当前是否已经为http2
		alreadyH2 := false
		for _, v := range jre.transport.TLSClientConfig.NextProtos {
			if v == "h2" {
				alreadyH2 = true
				break
			}
		}
		if !alreadyH2 {
			err = http2.ConfigureTransport(backTransport)
			if err != nil {
				return nil, err
			}
		}
	}
	jre.cli.Transport = backTransport
	resp.Resp, err = jre.cli.Do(jre.req)
	resetJr(jre)
	jrePool.Put(jre)
	return
}
