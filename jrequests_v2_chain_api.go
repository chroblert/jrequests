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
		//return nil
	}
	var err error
	jre = jrePool.Get().(*Jrequest)
	jre.cli.Jar, err = cookiejar.New(nil)
	if err != nil {
		jre.err = err
		return jre
	}
	urlObj, err := url.Parse(reqUrl)
	if err != nil {
		jre.err = err
		return jre
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
	if jr.err != nil {
		return
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
		jr.err = err
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
	if jr.err != nil {
		return
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
	if jr.err != nil {
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
	return jr
}

// 添加headers,1
func (jr *Jrequest) CAddHeaders(headers map[string]string) (jre *Jrequest) {
	if jr == nil {
		return nil
	}
	if jr.err != nil {
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
	return jr
}

// 设置body data,1
func (jr *Jrequest) CSetData(d interface{}) (jre *Jrequest) {
	if jr == nil {
		return nil
	}
	if jr.err != nil {
		return
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
	if jr.err != nil {
		return
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
	if jr.err != nil {
		return
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
	if jr.err != nil {
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

	return jr
}

// 添加cookies
func (jr *Jrequest) CAddCookies(cookies map[string]string) (jre *Jrequest) {
	if jr == nil {
		return nil
	}
	if jr.err != nil {
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

	return jr
}

// 设置是否转发
func (jr *Jrequest) CSetIsRedirect(isredirect bool) (jre *Jrequest) {
	if jr == nil {
		return nil
	}
	if jr.err != nil {
		return
	}
	jr.IsRedirect = isredirect

	return jr
}

// 设置http 2.0
func (jr *Jrequest) CSetHttpVersion(version int) (jre *Jrequest) {
	if jr == nil {
		return nil
	}
	if jr.err != nil {
		return
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
	if jr.err != nil {
		return
	}
	jr.IsVerifySSL = isverifyssl
	return jr
}

// 设置connection是否为长连接，keep-alive
func (jr *Jrequest) CSetKeepalive(iskeepalive bool) (jre *Jrequest) {
	if jr == nil {
		return nil
	}
	if jr.err != nil {
		return
	}
	jr.IsKeepAlive = iskeepalive
	return jr
}

// 设置发包后，是否发送RST包，用于缓解TIME_WAIT问题
func (jr *Jrequest) CSetRST(bSendRST bool) (jre *Jrequest) {
	if jr == nil {
		return nil
	}
	if jr.err != nil {
		return
	}
	jr.BSendRST = bSendRST
	return jr
}

// 设置capath
func (jr *Jrequest) CSetCAPath(CAPath string) (jre *Jrequest) {
	if jr == nil {
		return nil
	}
	if jr.err != nil {
		return
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
func (jr *Jrequest) CGetReq() (req *http.Request, err error) {
	if jr == nil {
		return nil, fmt.Errorf("jr is nil")
	}
	if jr.err != nil {
		return nil, jr.err
	}
	var reader io.Reader = bytes.NewReader(jr.Data)
	//var err error
	jr.req, err = http.NewRequest(jr.method, jr.Url, reader)
	if err != nil {
		jr.err = err
		return nil, err
	}
	// 设置headers
	for k, v := range jr.Headers {
		for _, v2 := range v {
			jr.req.Header.Add(k, v2)
		}
	}
	// 设置params
	if jr.Params != nil {
		query := jr.req.URL.Query()
		for paramKey, paramValue := range jr.Params {
			//query.Add(paramKey, paramValue)
			for _, v2 := range paramValue {
				query.Add(paramKey, v2)
			}
		}
		jr.req.URL.RawQuery = query.Encode()
	}
	// 设置connection
	jr.req.Close = !jr.IsKeepAlive
	req = jr.req
	// 设置短连接
	//jlog.Info(jr.req)
	//resetJr(jr)
	//jrePool.Put(jr)
	return req, nil
}

// CGetClient 获取client
func (jr *Jrequest) CGetClient() (client *http.Client, err error) {
	if jr == nil {
		err = fmt.Errorf("jr is nil")
		return
	}
	if jr.err != nil {
		err = jr.err
		return
	}
	// 设置短连接
	jr.transport.DisableKeepAlives = !jr.IsKeepAlive
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
	// 设置是否转发
	if !jr.IsRedirect {
		jr.cli.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			// 对302的location地址，不follow
			return http.ErrUseLastResponse
		}
	}
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
	// 缓解TIME_WAIT问题
	if jr.BSendRST {
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

	jr.cli.Transport = backTransport
	client = jr.cli
	return
}

// 发起请求
func (jr *Jrequest) CDo() (resp *Jresponse, err error) {
	if jr == nil {
		err = fmt.Errorf("jr is nil")
		return
	}
	// 在这里进行临时对象池的回收
	defer jrePool.Put(jr)
	defer resetJr(jr)
	if jr.err != nil {
		err = jr.err
		return
	}
	jr.req, err = jr.CGetReq()
	if err != nil {
		return nil, err
	}
	if jr.req == nil {
		err = fmt.Errorf("jr.req is nil")
		return
	}
	// 设置短连接
	jr.transport.DisableKeepAlives = !jr.IsKeepAlive
	resp = &Jresponse{}
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
	// 设置是否转发
	if !jr.IsRedirect {
		jr.cli.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			// 对302的location地址，不follow
			return http.ErrUseLastResponse
		}
	}
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
	// 缓解TIME_WAIT问题
	if jr.BSendRST {
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

	jr.cli.Transport = backTransport
	resp.Resp, err = jr.cli.Do(jr.req)

	return
}
