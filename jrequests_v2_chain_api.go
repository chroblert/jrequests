package jrequests

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/chroblert/jrequests/jfile"
	"golang.org/x/net/http2"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

func CRequest(reqMethod, reqUrl string, d ...interface{}) (jre *Jrequest) {
	switch reqMethod {
	case "GET":
	case "POST":
	case "PUT":
	case "HEAD":
	case "DELETE":
	default:
		return nil
	}
	var err error
	jre = jrePool.Get().(*Jrequest)
	jre.cli.Jar, err = cookiejar.New(nil)
	if err != nil {
		return nil
	}
	urlObj, err := url.Parse(reqUrl)
	if err != nil {
		return nil
	}
	jre.Params = urlObj.Query()
	urlStr := fmt.Sprintf("%s://%s%s", urlObj.Scheme, urlObj.Host, urlObj.Path)
	jre.Url = urlStr
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
	jre.method = reqMethod
	return
}

func CHead(reqUrl string, d ...interface{}) (jre *Jrequest) {
	return CRequest("HEAD", reqUrl, d)
}

func CGet(reqUrl string, d ...interface{}) (jre *Jrequest) {
	return CRequest("GET", reqUrl, d)
}

func CPost(reqUrl string, d ...interface{}) (jre *Jrequest) {
	return CRequest("POST", reqUrl, d)
}
func CPut(reqUrl string, d ...interface{}) (jre *Jrequest) {
	return CRequest("PUT", reqUrl, d)
}

// 设置代理
// proxy: eg:http://ip:port
func (jr *Jrequest) CSetProxy(proxy string) (jre *Jrequest) {
	if jr == nil {
		return nil
	}
	// TODO proxy格式校验
	if strings.TrimSpace(proxy) == "" {
		// 若为空，直接返回jr
		return jr
	}
	pUrl, err := url.Parse(proxy)
	if err != nil {
		//jr.transport.Proxy = nil
		//jlog.Error(err)
		return nil
	}
	jr.Proxy = pUrl
	//if proxy != "" {
	//	jr.transport.Proxy = func(request *http.Request) (*url.URL, error) {
	//		return url.Parse(proxy)
	//	}
	//} else {
	//	jr.transport.Proxy = nil
	//}
	return jr
}

// 设置超时
func (jr *Jrequest) CSetTimeout(timeout int) (jre *Jrequest) {
	if jr == nil {
		return nil
	}
	jr.Timeout = timeout
	//jr.cli.Timeout = time.Second * time.Duration(jr.Timeout)
	return jr
}

// 设置headers,1
func (jr *Jrequest) CSetHeaders(headers map[string][]string) (jre *Jrequest) {
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
func (jr *Jrequest) CAddHeaders(headers map[string]string) (jre *Jrequest) {
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
func (jr *Jrequest) CSetData(d interface{}) (jre *Jrequest) {
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
func (jr *Jrequest) CSetParams(params map[string][]string) (jre *Jrequest) {
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
func (jr *Jrequest) CAddParams(params map[string]string) (jre *Jrequest) {
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
func (jr *Jrequest) CSetCookies(cookies map[string]string) (jre *Jrequest) {
	if jr == nil {
		return nil
	}
	if jr.Cookies == nil {
		jr.Cookies = make([]*http.Cookie, len(cookies))
	}
	//bCookie := false
	//for k, _ := range jr.Headers {
	//	if k == "Cookie" {
	//		bCookie = true
	//		break
	//	}
	//}
	//// headers中有cookie
	//if bCookie {
	//
	//}
	if jr.Headers == nil {
		jr.Headers = make(map[string][]string)
	}
	cookieStrList := []string{}
	for kName, kVal := range cookies {
		tmpCookieStr := fmt.Sprintf("%s=%s", kName, kVal)
		cookieStrList = append(cookieStrList, tmpCookieStr)
	}
	jr.Headers["Cookie"] = cookieStrList

	return jr
}

// 添加cookies
func (jr *Jrequest) CAddCookies(cookies map[string]string) (jre *Jrequest) {
	if jr == nil {
		return nil
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

	return jr
}

// 设置是否转发
func (jr *Jrequest) CSetIsRedirect(isredirect bool) (jre *Jrequest) {
	if jr == nil {
		return nil
	}
	jr.IsRedirect = isredirect

	return jr
}

// 设置http 2.0
func (jr *Jrequest) CSetHttpVersion(version int) (jre *Jrequest) {
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
func (jr *Jrequest) CSetIsVerifySSL(isverifyssl bool) (jre *Jrequest) {
	if jr == nil {
		return nil
	}
	jr.IsVerifySSL = isverifyssl
	return jr
}

// 设置connection是否为长连接，keep-alive
func (jr *Jrequest) CSetKeepalive(iskeepalive bool) (jre *Jrequest) {
	if jr == nil {
		return nil
	}
	jr.IsKeepAlive = iskeepalive
	return jr
}

// 设置发包后，是否发送RST包，用于缓解TIME_WAIT问题
func (jr *Jrequest) CSetRST(bSendRST bool) (jre *Jrequest) {
	if jr == nil {
		return nil
	}
	jr.BSendRST = bSendRST
	return jr
}

// 设置capath
func (jr *Jrequest) CSetCAPath(CAPath string) (jre *Jrequest) {
	if jr == nil {
		return nil
	}
	jr.CAPath = CAPath
	return jr
}

func CSetReq(req *http.Request) (jr *Jrequest) {
	jr = jrePool.Get().(*Jrequest)
	// 设置params
	// 设置headers
	//for headerName,headerVals := range req.Header{
	//
	//}
	jr.Headers = req.Header
	//jr.Url = req.URL.RawQuery
	jr.Params = req.URL.Query()
	urlStr := fmt.Sprintf("%s://%s%s", req.URL.Scheme, req.URL.Host, req.URL.Path)
	jr.Url = urlStr
	//jlog.Info(req.URL.RawQuery, req.URL.Query(), jr.Url)
	//os.Exit(9)
	dataBytes, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil
	}
	jr.Data = dataBytes
	jr.method = req.Method
	if req.ProtoMajor == 2 {
		jr.HttpVersion = 2
	} else if req.ProtoMajor == 1 {
		jr.HttpVersion = 1
	}
	return jr
}

// 获取请求
func (jre *Jrequest) CGetReq() (req *http.Request, err error) {
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
	// 设置connection
	jre.req.Close = !jre.IsKeepAlive
	req = jre.req
	// 设置短连接
	//jlog.Info(jre.req)
	resetJr(jre)
	jrePool.Put(jre)
	return req, nil
}

// 发起请求
func (jre *Jrequest) CDo() (resp *Jresponse, err error) {
	jre.req, err = jre.CGetReq()
	if err != nil {
		return nil, err
	}
	// 设置短连接
	jre.transport.DisableKeepAlives = !jre.IsKeepAlive
	resp = &Jresponse{}
	//jlog.Info(jre.req)

	// 设置代理
	if jre.Proxy != nil {
		jre.transport.Proxy = func(request *http.Request) (*url.URL, error) {
			return jre.Proxy, nil
		}
	} else {
		jre.transport.Proxy = nil
	}
	// 设置超时
	jre.cli.Timeout = time.Second * time.Duration(jre.Timeout)
	// 设置是否转发
	if !jre.IsRedirect {
		jre.cli.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			// 对302的location地址，不follow
			return http.ErrUseLastResponse
		}
	}
	// 设置是否验证服务端证书
	if !jre.IsVerifySSL {
		if jre.transport.TLSClientConfig != nil {
			jre.transport.TLSClientConfig.InsecureSkipVerify = true
		} else {
			jre.transport.TLSClientConfig = &tls.Config{
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
		if isExsit, _ := jfile.PathExists(jre.CAPath); isExsit {
			// 枚举当前目录下的文件
			caFilenames, _ := jfile.GetFilenamesByDir(jre.CAPath)
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
		if jre.transport.TLSClientConfig != nil {
			jre.transport.TLSClientConfig.RootCAs = rootCAPool
		} else {
			jre.transport.TLSClientConfig = &tls.Config{
				RootCAs: rootCAPool,
			}
		}
		jre.transport.TLSClientConfig = &tls.Config{
			RootCAs: rootCAPool,
		}
	}
	// 设置transport
	backTransport := jre.transport
	//tmp := *jr.transport
	//backTransport := &tmp
	if jre.HttpVersion == 2 {
		// 判断当前是否已经为http2
		alreadyH2 := false
		if jre.transport.TLSClientConfig != nil {
			for _, v := range jre.transport.TLSClientConfig.NextProtos {
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
	// 缓解TIME_WAIT问题
	if jre.BSendRST {
		backTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 30 * time.Second,
			}
			conn, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			tcpConn, ok := conn.(*net.TCPConn)
			if ok {
				tcpConn.SetLinger(0)
				return tcpConn, nil
			}
			return conn, nil
		}
	}

	jre.cli.Transport = backTransport
	resp.Resp, err = jre.cli.Do(jre.req)
	resetJr(jre)
	jrePool.Put(jre)
	return
}
