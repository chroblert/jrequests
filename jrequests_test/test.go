package main

import (
	"fmt"
	"github.com/chroblert/jasync"
	"github.com/chroblert/jlog"
	"github.com/chroblert/jrequests"
)

func main() {
	//new_requests()
	async_req()
}

func new_requests() {
	req, _ := jrequests.New()
	//req.SetIsVerifySSL(false)
	req.SetProxy("http://localhost:8080")
	req.SetIsVerifySSL(false)
	req.SetHttpVersion(2)
	req.SetKeepalive(false)
	_, err := req.Get("https://myip.ipip.net")
	if err != nil {
		jlog.Error(err)
		return
	}
	a := jasync.New()
	a.Add("", jrequests.CGet("https://myip.ipip.net/11").CAddHeaders(map[string]string{"kkkk": "t====ddd"}).CSetIsVerifySSL(false).CSetHttpVersion(2).CSetProxy("http://localhost:8080").CSetTimeout(3).CDo, nil)
	a.Add("", jrequests.CGet("https://myip.ipip.net/12").CAddHeaders(map[string]string{"ddd": "t====ddd"}).CSetIsVerifySSL(false).CSetHttpVersion(2).CSetProxy("http://localhost:8080").CSetTimeout(3).CDo, nil)
	req.AddHeaders(map[string]string{"test": "header test"})
	for i := 3; i < 6; i++ {
		a.Add("", req.Get, nil, "https://myip.ipip.net?"+fmt.Sprintf("%d", i))
	}
	a.Run(-1)
	a.Wait()
	a.PrintAllTaskStatus(true)
	return
	req.SetHttpVersion(1)
	_, err = req.Get("https://ipinfo.io")
	if err != nil {
		jlog.Error(err)
		return
	}
	//req.SetHttpVersion(2)
	_, err = req.Get("https://myip.ipip.net")
	if err != nil {
		jlog.Error(err)
		return
	}
	_, err = jrequests.CGet("https://ipinfo.io").CSetIsVerifySSL(false).CSetHttpVersion(2).CSetProxy("http://localhost:8080").CSetTimeout(1).CDo()
	if err != nil {
		jlog.Error(err)
		//jlog.NFatal("not find arcsight ArcMC in",target)
		return
	}
}

func async_req() {
	a := jasync.NewAR(5)
	for i := 0; i < 2; i++ {
		a.Init("").CAdd(func() string {
			req, err := jrequests.CRequest("GET", "https://ipinfo.io/?1=2&b=4").
				CSetIsVerifySSL(false).
				CSetHttpVersion(2).
				//CSetProxy("http://localhost:8080").
				CSetHeaders(map[string][]string{
					"User-Agent": {"curl\\7.4"},
				}).
				CSetCookies(map[string]string{
					"1": "1",
					"2": "3",
				}).CAddCookies(map[string]string{
				"3": "4", "5": "6",
			}).
				CSetTimeout(3).CGetReq()
			jlog.Error(err)
			resp, err := jrequests.CSetReq(req).CSetParams(map[string][]string{
				"t1": {"1q1q", "4r4r"},
				//}).CSetProxy("http://localhost:8080").CDo()
			}).CSetProxy("").CDo()
			jlog.Error(err)
			return string(resp.Body())
		}).CAdd(func(body string) {
			jlog.Info(body)
		}).CDO()
	}
	a.Wait()

}
