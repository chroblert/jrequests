package jrequests

import "io/ioutil"

// 返回响应的body
func (jrs *Jresponse) Body() []byte {
	if jrs.Resp == nil {
		return nil
	}
	defer jrs.Resp.Body.Close()
	res, err := ioutil.ReadAll(jrs.Resp.Body)
	if err != nil {
		return nil
	}
	return res
}
