package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

const (
	accountType = "02"
	appID       = "8025431004"
	clientType  = "10020"
	versionName = "6.2"
	webURL      = "https://cloud.189.cn"
	authURL     = "https://open.e.189.cn"
	apiURL      = "https://api.cloud.189.cn"
	returnURL   = "https://m.cloud.189.cn/zhuanti/2020/loginErrorPc/index.html"
	pcName      = "TELEPC"
	channelID   = "web_cloud.189.cn"
	httpTimeout = 10 * time.Second
)

var ErrNotFound = errors.New("not found")

// Cloud189Client 封装天翼云盘登录态和 API 调用。
type Cloud189Client struct {
	cfg    Cloud189Config
	client *resty.Client

	mu        sync.Mutex
	token     *AppSessionResp
	loginBase *BaseLoginParam
	statePath string
	state     Cloud189State
}

// NewCloud189Client 创建客户端并在启动阶段完成一次登录/续期，确保服务可用后再对外提供 WebDAV。
func NewCloud189Client(cfg Cloud189Config, statePath string) (*Cloud189Client, error) {
	if cfg.Type == "" {
		cfg.Type = "personal"
	}
	if cfg.RootFolderID == "" && cfg.Type == "personal" {
		cfg.RootFolderID = "-11"
	}
	jar, _ := cookiejar.New(nil)
	c := &Cloud189Client{
		cfg:       cfg,
		statePath: statePath,
		client: resty.New().
			SetTimeout(httpTimeout).
			SetCookieJar(jar).
			SetHeaders(map[string]string{
				"Accept":  "application/json;charset=UTF-8",
				"Referer": webURL,
			}),
	}
	if err := c.loadState(); err != nil {
		return nil, err
	}
	if err := c.reauthenticate(context.Background()); err != nil {
		return nil, err
	}
	if c.cfg.Type == "family" && c.cfg.FamilyID == "" {
		familyID, err := c.getFamilyID(context.Background())
		if err != nil {
			return nil, err
		}
		c.cfg.FamilyID = familyID
	}
	return c, nil
}

// RootEntry 返回逻辑上的云盘根目录。
func (c *Cloud189Client) RootEntry() Entry {
	return Entry{
		ID:    c.cfg.RootFolderID,
		Name:  "",
		IsDir: true,
	}
}

// List 读取目录下一级子项列表。
// 调用方主要是 PathCache.listDir，正常情况下目录扫描都会经过这里。
func (c *Cloud189Client) List(ctx context.Context, folderID string) ([]Entry, error) {
	if err := c.ensureSession(ctx); err != nil {
		return nil, err
	}
	isFamily := c.cfg.Type == "family"
	var out []Entry
	for pageNum := 1; ; pageNum++ {
		resp, err := c.listFilesPage(ctx, folderID, pageNum, 1000, isFamily)
		if err != nil {
			return nil, err
		}
		if resp.FileListAO.Count == 0 {
			break
		}
		for _, folder := range resp.FileListAO.FolderList {
			out = append(out, Entry{
				ID:         string(folder.ID),
				Name:       folder.Name,
				ModifiedAt: time.Time(folder.LastOpTime),
				CreatedAt:  time.Time(folder.CreateDate),
				IsDir:      true,
			})
		}
		for _, file := range resp.FileListAO.FileList {
			out = append(out, Entry{
				ID:         string(file.ID),
				Name:       file.Name,
				Size:       file.Size,
				ModifiedAt: time.Time(file.LastOpTime),
				CreatedAt:  time.Time(file.CreateDate),
				IsDir:      false,
			})
		}
	}
	return out, nil
}

// DirectLink 为文件申请真实下载地址。
// 调用方只有 handleRead 的 GET 路径，HEAD 不会调用它。
func (c *Cloud189Client) DirectLink(ctx context.Context, fileID string) (string, error) {
	if err := c.ensureSession(ctx); err != nil {
		return "", err
	}
	isFamily := c.cfg.Type == "family"
	fullURL := apiURL
	if isFamily {
		fullURL += "/family/file"
	}
	fullURL += "/getFileDownloadUrl.action"

	var download struct {
		URL string `json:"fileDownloadUrl"`
	}
	if _, err := c.get(fullURL, func(r *resty.Request) {
		r.SetContext(ctx)
		r.SetQueryParam("fileId", fileID)
		if isFamily {
			r.SetQueryParam("familyId", c.cfg.FamilyID)
			return
		}
		r.SetQueryParams(map[string]string{"dt": "3", "flag": "1"})
	}, &download, isFamily); err != nil {
		return "", err
	}
	return strings.Replace(strings.ReplaceAll(download.URL, "&amp;", "&"), "http://", "https://", 1), nil
}

// ensureSession 确保当前请求拥有可用登录态。
// 对于 rclone 挂载场景，这里只保证本地内存里已有令牌，不主动探测远端会话。
func (c *Cloud189Client) ensureSession(ctx context.Context) error {
	c.mu.Lock()
	hasToken := c.token != nil
	c.mu.Unlock()
	if hasToken {
		return nil
	}
	return c.reauthenticate(ctx)
}

// reauthenticate 在本地会话缺失或服务端明确返回失效时执行一次重认证。
func (c *Cloud189Client) reauthenticate(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != nil {
		return nil
	}
	return c.reauthenticateLocked(ctx)
}

func (c *Cloud189Client) reauthenticateLocked(ctx context.Context) error {
	if c.state.RefreshToken != "" {
		c.token = &AppSessionResp{RefreshToken: c.state.RefreshToken}
		if err := c.refreshToken(ctx); err == nil {
			return nil
		}
		c.token = nil
	}
	return c.loginByPassword(ctx)
}

// loginByPassword 使用账号密码执行完整登录流程。
// 当 refresh token 不可用或失效时，ensureSession 会回退到这里。
func (c *Cloud189Client) loginByPassword(ctx context.Context) error {
	if c.cfg.Username == "" || c.cfg.Password == "" {
		return errors.New("cloud189 username/password is required")
	}
	if err := c.initLoginParam(ctx); err != nil {
		return err
	}

	param := c.loginBase
	var loginResp LoginResp
	_, err := c.client.R().
		SetContext(ctx).
		ForceContentType("application/json;charset=UTF-8").
		SetResult(&loginResp).
		SetHeaders(map[string]string{"REQID": param.ReqID, "lt": param.Lt}).
		SetFormData(map[string]string{
			"appKey":       appID,
			"accountType":  accountType,
			"userName":     param.RSAUsername,
			"password":     param.RSAPassword,
			"validateCode": "",
			"captchaToken": param.CaptchaToken,
			"returnUrl":    returnURL,
			"dynamicCheck": "FALSE",
			"clientType":   clientType,
			"cb_SaveName":  "1",
			"isOauth2":     "false",
			"state":        "",
			"paramId":      param.ParamID,
		}).
		Post(authURL + "/api/logbox/oauth2/loginSubmit.do")
	if err != nil {
		return err
	}
	if loginResp.ToURL == "" {
		return fmt.Errorf("login failed: %s", loginResp.Msg)
	}

	var errResp RespErr
	var token AppSessionResp
	_, err = c.client.R().
		SetContext(ctx).
		SetResult(&token).
		SetError(&errResp).
		SetQueryParams(clientSuffix()).
		SetQueryParam("redirectURL", loginResp.ToURL).
		Post(apiURL + "/getSessionForPC.action")
	if err != nil {
		return err
	}
	if errResp.HasError() {
		return &errResp
	}
	if token.ResCode != 0 {
		return errors.New(token.ResMessage)
	}
	c.token = &token
	return c.storeRefreshToken(token.RefreshToken)
}

// refreshSession 用 access token 刷新会话细节。
// 如果云端返回 open token 无效，会继续尝试 refreshToken。
func (c *Cloud189Client) refreshSession(ctx context.Context) error {
	var errResp RespErr
	var session UserSessionResp
	_, err := c.client.R().
		SetContext(ctx).
		SetResult(&session).
		SetError(&errResp).
		SetQueryParams(clientSuffix()).
		SetQueryParams(map[string]string{
			"appId":       appID,
			"accessToken": c.token.AccessToken,
		}).
		SetHeader("X-Request-ID", uuid.NewString()).
		Get(apiURL + "/getSessionForPC.action")
	if err != nil {
		return err
	}
	if errResp.HasError() {
		if errResp.ResCode == "UserInvalidOpenToken" {
			return c.refreshToken(ctx)
		}
		return &errResp
	}
	c.token.UserSessionResp = session
	return nil
}

// refreshToken 用 refresh token 换取新的 access token 和会话信息。
func (c *Cloud189Client) refreshToken(ctx context.Context) error {
	var errResp RespErr
	var token AppSessionResp
	_, err := c.client.R().
		SetContext(ctx).
		SetResult(&token).
		SetError(&errResp).
		ForceContentType("application/json;charset=UTF-8").
		SetFormData(map[string]string{
			"clientId":     appID,
			"refreshToken": c.token.RefreshToken,
			"grantType":    "refresh_token",
			"format":       "json",
		}).
		Post(authURL + "/api/oauth2/refreshToken.do")
	if err != nil {
		return err
	}
	if errResp.HasError() {
		return c.loginByPassword(ctx)
	}
	c.token = &token
	if err := c.storeRefreshToken(token.RefreshToken); err != nil {
		return err
	}
	return c.refreshSession(ctx)
}

func (c *Cloud189Client) invalidateSession() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = nil
}

// getFamilyID 在家庭云模式下自动探测 family_id。
func (c *Cloud189Client) getFamilyID(ctx context.Context) (string, error) {
	var resp struct {
		FamilyInfoResp []struct {
			FamilyID   int64  `json:"familyId"`
			RemarkName string `json:"remarkName"`
		} `json:"familyInfoResp"`
	}
	if _, err := c.get(apiURL+"/family/manage/getFamilyList.action", nil, &resp, true); err != nil {
		return "", err
	}
	if len(resp.FamilyInfoResp) == 0 {
		return "", errors.New("cannot determine family_id automatically")
	}
	for _, info := range resp.FamilyInfoResp {
		if strings.Contains(c.token.LoginName, info.RemarkName) {
			return fmt.Sprint(info.FamilyID), nil
		}
	}
	return fmt.Sprint(resp.FamilyInfoResp[0].FamilyID), nil
}

// listFilesPage 请求单页目录内容，是 List 的底层分页实现。
func (c *Cloud189Client) listFilesPage(ctx context.Context, folderID string, pageNum int, pageSize int, isFamily bool) (*Cloud189FilesResp, error) {
	fullURL := apiURL
	if isFamily {
		fullURL += "/family/file"
	}
	fullURL += "/listFiles.action"
	var resp Cloud189FilesResp
	_, err := c.get(fullURL, func(r *resty.Request) {
		r.SetContext(ctx)
		r.SetQueryParams(map[string]string{
			"folderId":   folderID,
			"fileType":   "0",
			"mediaAttr":  "0",
			"iconOption": "5",
			"pageNum":    fmt.Sprint(pageNum),
			"pageSize":   fmt.Sprint(pageSize),
		})
		if isFamily {
			r.SetQueryParams(map[string]string{
				"familyId":   c.cfg.FamilyID,
				"orderBy":    "1",
				"descending": "false",
			})
			return
		}
		r.SetQueryParams(map[string]string{
			"recursive":  "0",
			"orderBy":    "filename",
			"descending": "false",
		})
	}, &resp, isFamily)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// get 是 GET 请求的便捷包装。
func (c *Cloud189Client) get(fullURL string, callback func(*resty.Request), resp any, isFamily bool) ([]byte, error) {
	return c.request(fullURL, http.MethodGet, callback, nil, resp, isFamily, false)
}

// request 是所有云盘 API 的统一入口：
// 1. 挂鉴权头
// 2. 发请求
// 3. 发现会话失效时触发一次被动续期
// 4. 成功后返回原始响应体
func (c *Cloud189Client) request(fullURL, method string, callback func(*resty.Request), params Params, resp any, isFamily bool, retried bool) ([]byte, error) {
	if c.token == nil {
		return nil, errors.New("not logged in")
	}
	req := c.client.R().SetQueryParams(clientSuffix())
	paramData := c.encryptParams(params, isFamily)
	if paramData != "" {
		req.SetQueryParam("params", paramData)
	}
	req.SetHeaders(c.signatureHeader(fullURL, method, paramData, isFamily))
	var errResp RespErr
	req.SetError(&errResp)
	if callback != nil {
		callback(req)
	}
	if resp != nil {
		req.SetResult(resp)
	}
	res, err := req.Execute(method, fullURL)
	if err != nil {
		return nil, err
	}
	body := res.Body()
	if strings.Contains(string(body), "userSessionBO is null") || strings.Contains(string(body), "InvalidSessionKey") {
		if retried {
			return nil, errors.New("cloud189 session invalid after reauthentication")
		}
		c.invalidateSession()
		if err := c.reauthenticate(req.Context()); err != nil {
			return nil, err
		}
		return c.request(fullURL, method, callback, params, resp, isFamily, true)
	}
	if errResp.HasError() {
		return nil, &errResp
	}
	return body, nil
}

// initLoginParam 拉取登录页和加密参数，为密码登录准备 RSA 密文。
func (c *Cloud189Client) initLoginParam(ctx context.Context) error {
	jar, _ := cookiejar.New(nil)
	c.client.SetCookieJar(jar)
	res, err := c.client.R().
		SetContext(ctx).
		SetQueryParams(map[string]string{
			"appId":      appID,
			"clientType": clientType,
			"returnURL":  returnURL,
			"timeStamp":  fmt.Sprint(timestamp()),
		}).
		Get(webURL + "/api/portal/unifyLoginForPC.action")
	if err != nil {
		return err
	}
	page := res.String()
	baseParam := &BaseLoginParam{
		CaptchaToken: mustMatch(page, `'captchaToken' value='(.+?)'`),
		Lt:           mustMatch(page, `lt = "(.+?)"`),
		ParamID:      mustMatch(page, `paramId = "(.+?)"`),
		ReqID:        mustMatch(page, `reqId = "(.+?)"`),
	}

	var encryptConf EncryptConfResp
	_, err = c.client.R().
		SetContext(ctx).
		ForceContentType("application/json;charset=UTF-8").
		SetResult(&encryptConf).
		SetFormData(map[string]string{"appId": appID}).
		Post(authURL + "/api/logbox/config/encryptConf.do")
	if err != nil {
		return err
	}
	publicKey := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", encryptConf.Data.PubKey)
	baseParam.RSAUsername = encryptConf.Data.Pre + rsaEncrypt(publicKey, c.cfg.Username)
	baseParam.RSAPassword = encryptConf.Data.Pre + rsaEncrypt(publicKey, c.cfg.Password)
	c.loginBase = baseParam
	return nil
}

// signatureHeader 生成天翼云盘接口要求的签名请求头。
func (c *Cloud189Client) signatureHeader(fullURL, method, params string, isFamily bool) map[string]string {
	dateOfGMT := time.Now().UTC().Format(http.TimeFormat)
	sessionKey := c.token.SessionKey
	sessionSecret := c.token.SessionSecret
	if isFamily {
		sessionKey = c.token.FamilySessionKey
		sessionSecret = c.token.FamilySessionSecret
	}
	return map[string]string{
		"Date":         dateOfGMT,
		"SessionKey":   sessionKey,
		"X-Request-ID": uuid.NewString(),
		"Signature":    signatureOfHMAC(sessionSecret, sessionKey, method, fullURL, dateOfGMT, params),
	}
}

// encryptParams 对 params 做接口要求的 AES 加密。
func (c *Cloud189Client) encryptParams(params Params, isFamily bool) string {
	secret := c.token.SessionSecret
	if isFamily {
		secret = c.token.FamilySessionSecret
	}
	if params == nil {
		return ""
	}
	return aesECBEncrypt(params.Encode(), secret[:16])
}

// clientSuffix 生成公共查询参数。
func clientSuffix() map[string]string {
	now := time.Now().UnixNano()
	return map[string]string{
		"clientType": pcName,
		"version":    versionName,
		"channelId":  channelID,
		"rand":       fmt.Sprintf("%d_%d", now%1e5, now%1e10),
	}
}

// signatureOfHMAC 计算接口签名。
func signatureOfHMAC(sessionSecret, sessionKey, method, fullURL, dateOfGMT, params string) string {
	urlPath := regexp.MustCompile(`://[^/]+((/[^/\s?#]+)*)`).FindStringSubmatch(fullURL)[1]
	mac := hmac.New(sha1.New, []byte(sessionSecret))
	data := fmt.Sprintf("SessionKey=%s&Operate=%s&RequestURI=%s&Date=%s", sessionKey, method, urlPath, dateOfGMT)
	if params != "" {
		data += "&params=" + params
	}
	mac.Write([]byte(data))
	return strings.ToUpper(hex.EncodeToString(mac.Sum(nil)))
}

// rsaEncrypt 使用服务端下发的公钥加密用户名和密码。
func rsaEncrypt(publicKey, plain string) string {
	block, _ := pem.Decode([]byte(publicKey))
	pub, _ := x509.ParsePKIXPublicKey(block.Bytes)
	cipher, _ := rsa.EncryptPKCS1v15(rand.Reader, pub.(*rsa.PublicKey), []byte(plain))
	return strings.ToUpper(hex.EncodeToString(cipher))
}

// aesECBEncrypt 以接口约定的 ECB 方式加密参数串。
func aesECBEncrypt(data, key string) string {
	block, _ := aes.NewCipher([]byte(key))
	padding := block.BlockSize() - len(data)%block.BlockSize()
	padded := append([]byte(data), bytes.Repeat([]byte{byte(padding)}, padding)...)
	encrypted := make([]byte, len(padded))
	size := block.BlockSize()
	for src, dst := padded, encrypted; len(src) > 0; src, dst = src[size:], dst[size:] {
		block.Encrypt(dst[:size], src[:size])
	}
	return strings.ToUpper(hex.EncodeToString(encrypted))
}

// timestamp 返回毫秒级 UTC 时间戳。
func timestamp() int64 {
	return time.Now().UTC().UnixNano() / 1e6
}

// mustMatch 从登录页 HTML/JS 中提取指定字段。
func mustMatch(body, pattern string) string {
	match := regexp.MustCompile(pattern).FindStringSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

// BaseLoginParam 保存密码登录前置接口解析出的参数。
type BaseLoginParam struct {
	CaptchaToken string
	Lt           string
	ParamID      string
	ReqID        string
	RSAUsername  string
	RSAPassword  string
}

// EncryptConfResp 是获取登录加密公钥的响应结构。
type EncryptConfResp struct {
	Data struct {
		Pre    string `json:"pre"`
		PubKey string `json:"pubKey"`
	} `json:"data"`
}

// LoginResp 是密码登录提交后的响应结构。
type LoginResp struct {
	Msg   string `json:"msg"`
	ToURL string `json:"toUrl"`
}

// RespErr 兼容不同接口返回格式的错误结构。
type RespErr struct {
	ResCode    any      `json:"res_code"`
	ResMessage string   `json:"res_message"`
	ErrorText  string   `json:"error"`
	XMLName    xml.Name `xml:"error"`
	Code       string   `json:"code" xml:"code"`
	Message    string   `json:"message" xml:"message"`
	Msg        string   `json:"msg"`
	ErrorCode  string   `json:"errorCode"`
	ErrorMsg   string   `json:"errorMsg"`
}

// HasError 判断响应体中是否包含业务错误。
func (e *RespErr) HasError() bool {
	switch v := e.ResCode.(type) {
	case float64:
		return v != 0
	case string:
		return v != ""
	}
	return (e.Code != "" && e.Code != "SUCCESS") || e.ErrorCode != "" || e.ErrorText != ""
}

// Error 返回适合日志和 HTTP 错误透传的错误消息。
func (e *RespErr) Error() string {
	if e.ResMessage != "" {
		return e.ResMessage
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Msg != "" {
		return e.Msg
	}
	if e.ErrorMsg != "" {
		return e.ErrorMsg
	}
	if e.ErrorText != "" {
		return e.ErrorText
	}
	return "cloud189 request failed"
}

// UserSessionResp / AppSessionResp / Cloud189FilesResp 等结构用于承接接口响应。
type UserSessionResp struct {
	ResCode             int    `json:"res_code"`
	ResMessage          string `json:"res_message"`
	LoginName           string `json:"loginName"`
	SessionKey          string `json:"sessionKey"`
	SessionSecret       string `json:"sessionSecret"`
	FamilySessionKey    string `json:"familySessionKey"`
	FamilySessionSecret string `json:"familySessionSecret"`
}

type AppSessionResp struct {
	UserSessionResp
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

// Cloud189State 保存程序自动续期所需的内部状态，不暴露给常规用户配置。
type Cloud189State struct {
	RefreshToken string `json:"refresh_token"`
}

type Cloud189FilesResp struct {
	FileListAO struct {
		Count      int              `json:"count"`
		FileList   []Cloud189File   `json:"fileList"`
		FolderList []Cloud189Folder `json:"folderList"`
	} `json:"fileListAO"`
}

type Cloud189File struct {
	ID         JSONString `json:"id"`
	Name       string     `json:"name"`
	Size       int64      `json:"size"`
	LastOpTime JSONTime   `json:"lastOpTime"`
	CreateDate JSONTime   `json:"createDate"`
}

type Cloud189Folder struct {
	ID         JSONString `json:"id"`
	Name       string     `json:"name"`
	LastOpTime JSONTime   `json:"lastOpTime"`
	CreateDate JSONTime   `json:"createDate"`
}

type JSONTime time.Time

// UnmarshalJSON 兼容天翼云盘接口里出现过的两种时间格式。
func (t *JSONTime) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	for _, layout := range []string{"2006-01-02 15:04:05", "Jan 2, 2006 15:04:05 PM"} {
		if tm, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			*t = JSONTime(tm)
			return nil
		}
	}
	*t = JSONTime(time.Time{})
	return nil
}

type JSONString string

// UnmarshalJSON 兼容字符串和数字两种 ID 表达形式。
func (s *JSONString) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err == nil {
		*s = JSONString(str)
		return nil
	}
	var num json.Number
	if err := json.Unmarshal(b, &num); err == nil {
		*s = JSONString(num.String())
		return nil
	}
	*s = JSONString(strings.Trim(string(b), `"`))
	return nil
}

func (c *Cloud189Client) loadState() error {
	if c.statePath == "" {
		return nil
	}
	if _, err := os.Stat(c.statePath); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return ReadJSON(c.statePath, &c.state)
}

func (c *Cloud189Client) storeRefreshToken(refreshToken string) error {
	c.state.RefreshToken = refreshToken
	if c.statePath == "" {
		return nil
	}
	return WriteJSON(c.statePath, &c.state)
}

type Params map[string]string

// Encode 将参数按 key 排序后编码，保证签名和加密输入稳定。
func (p Params) Encode() string {
	if p == nil {
		return ""
	}
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, key := range keys {
		parts = append(parts, key+"="+p[key])
	}
	return strings.Join(parts, "&")
}
