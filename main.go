package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	Server   ServerConfig   `json:"server"`
	Cloud189 Cloud189Config `json:"cloud189"`
	Security SecurityConfig `json:"security"`
}

// ServerConfig 描述本地 WebDAV 服务监听参数。
type ServerConfig struct {
	Listen   string `json:"listen"`
	BasePath string `json:"base_path"`
}

// Cloud189Config 描述天翼云盘登录、目录范围和缓存策略。
type Cloud189Config struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	Type         string `json:"type"`
	FamilyID     string `json:"family_id"`
	RootFolderID string `json:"root_folder_id"`
}

// SecurityConfig 描述 root 启动后的降权目标。
type SecurityConfig struct {
	RunAsUID int `json:"run_as_uid"`
	RunAsGID int `json:"run_as_gid"`
}

// Entry 是统一的目录项模型，被 WebDAV 响应和路径缓存共同使用。
type Entry struct {
	ID         string
	Name       string
	Size       int64
	ModifiedAt time.Time
	CreatedAt  time.Time
	IsDir      bool
}

type Server struct {
	dav   string
	cloud *Cloud189Client
	cache *PathCache
}

// main 是程序启动入口，顺序完成：加载配置、登录云盘、启动 WebDAV、最后降权常驻。
func main() {
	cfg, configPath, statePath, err := LoadConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	client, err := NewCloud189Client(cfg.Cloud189, statePath)
	if err != nil {
		log.Fatalf("init cloud189 client: %v", err)
	}
	davPath := cleanBasePath(cfg.Server.BasePath)
	srv := &Server{
		dav:   davPath,
		cloud: client,
		cache: NewPathCache(),
	}
	log.Printf("config: %s", configPath)
	log.Printf("webdav: %s", publicDAVURL(cfg.Server.Listen, davPath))
	log.Printf("cloud189 type: %s", cfg.Cloud189.Type)
	server := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve http: %v", err)
		}
	}()
	if err := maybeDropPrivileges(cfg.Security); err != nil {
		log.Fatalf("drop privileges: %v", err)
	}
	select {}
}

// LoadConfig 从 ~/.config/cloud189/config.json 读取配置；首次启动会写入默认配置。
// 同时会把旧版本遗留在 config.json 里的 refresh token 迁移到内部 state.json。
func LoadConfig() (*Config, string, string, error) {
	dir, err := os.UserHomeDir()
	if err != nil {
		return nil, "", "", err
	}
	configDir := filepath.Join(dir, ".config", "cloud189")
	configPath := filepath.Join(configDir, "config.json")
	statePath := filepath.Join(configDir, "state.json")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return nil, "", "", err
	}
	if _, err := os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		cfg := DefaultConfig()
		if err := WriteJSON(configPath, cfg); err != nil {
			return nil, "", "", err
		}
		return cfg, configPath, statePath, nil
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, "", "", err
	}
	cfg := DefaultConfig()
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, "", "", err
	}
	cfg.Server.BasePath = cleanBasePath(cfg.Server.BasePath)
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = "127.0.0.1:5244"
	}
	if cfg.Cloud189.Type == "" {
		cfg.Cloud189.Type = "personal"
	}
	if cfg.Cloud189.RootFolderID == "" && cfg.Cloud189.Type == "personal" {
		cfg.Cloud189.RootFolderID = "-11"
	}

	var legacy struct {
		Cloud189 struct {
			RefreshToken string `json:"refresh_token"`
		} `json:"cloud189"`
	}
	if err := json.Unmarshal(raw, &legacy); err != nil {
		return nil, "", "", err
	}
	if legacy.Cloud189.RefreshToken != "" {
		if _, err := os.Stat(statePath); errors.Is(err, os.ErrNotExist) {
			if err := WriteJSON(statePath, &Cloud189State{RefreshToken: legacy.Cloud189.RefreshToken}); err != nil {
				return nil, "", "", err
			}
		}
	}
	normalized, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, "", "", err
	}
	normalized = append(normalized, '\n')
	if !bytes.Equal(raw, normalized) {
		if err := os.WriteFile(configPath, normalized, 0o600); err != nil {
			return nil, "", "", err
		}
	}
	return cfg, configPath, statePath, nil
}

// DefaultConfig 返回初始化配置文件时使用的默认值。
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Listen:   "127.0.0.1:5244",
			BasePath: "/dav",
		},
		Cloud189: Cloud189Config{
			Type:         "personal",
			RootFolderID: "-11",
		},
		Security: SecurityConfig{
			RunAsUID: 65534,
			RunAsGID: 65534,
		},
	}
}

// maybeDropPrivileges 在 root 启动时将进程切换到低权限用户。
// 调用方只有 main，会在 WebDAV 服务启动后执行。
func maybeDropPrivileges(cfg SecurityConfig) error {
	if os.Geteuid() != 0 {
		return nil
	}
	uid, gid := cfg.RunAsUID, cfg.RunAsGID
	if uid == 0 && gid == 0 {
		uid, gid = nobodyUIDGID()
	}
	if gid != 0 {
		if err := syscall.Setgid(gid); err != nil {
			return fmt.Errorf("setgid %d: %w", gid, err)
		}
	}
	if uid != 0 {
		if err := syscall.Setuid(uid); err != nil {
			return fmt.Errorf("setuid %d: %w", uid, err)
		}
	}
	log.Printf("privileges dropped to uid=%d gid=%d", os.Geteuid(), os.Getegid())
	return nil
}

// nobodyUIDGID 返回默认降权目标。
// Linux 上通常 nobody/nogroup 对应 65534:65534，这里直接使用该惯例值，避免额外依赖系统账号查询。
func nobodyUIDGID() (int, int) {
	return 65534, 65534
}

// ReadJSON 读取 JSON 配置文件并反序列化到目标对象。
func ReadJSON(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

// WriteJSON 将对象按缩进格式写回配置文件，并限制为仅属主可读写。
func WriteJSON(path string, in any) error {
	data, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

// cleanBasePath 规范化 WebDAV 基础路径，空值时回退到 /dav。
func cleanBasePath(p string) string {
	if p == "" || p == "/" {
		return "/dav"
	}
	return path.Clean("/" + p)
}

// publicDAVURL 返回日志和文档里使用的无凭证 WebDAV 地址。
func publicDAVURL(listenAddr, basePath string) string {
	host := listenAddr
	if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}
	return "http://" + host + cleanBasePath(basePath)
}

// routes 是整个 HTTP 服务的入口分发器，只暴露只读 WebDAV 能力。
func (s *Server) routes() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, s.dav+"/", http.StatusFound)
			return
		}
		if !strings.HasPrefix(r.URL.Path, s.dav) {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodOptions:
			s.handleOptions(w)
		case "PROPFIND":
			s.handlePropfind(w, r)
		case http.MethodGet, http.MethodHead:
			s.handleRead(w, r)
		default:
			w.Header().Set("Allow", "OPTIONS, PROPFIND, GET, HEAD")
			http.Error(w, "read-only webdav", http.StatusMethodNotAllowed)
		}
	})
}

// relativePath 将请求 URL 转成云盘内部使用的规范路径。
func (s *Server) relativePath(p string) string {
	raw := strings.TrimPrefix(p, s.dav)
	if raw == "" {
		return "/"
	}
	raw = "/" + strings.TrimPrefix(raw, "/")
	cleaned := path.Clean(raw)
	if cleaned == "." {
		return "/"
	}
	return cleaned
}

// handleOptions 响应 WebDAV 客户端的能力探测请求。
func (s *Server) handleOptions(w http.ResponseWriter) {
	w.Header().Set("DAV", "1")
	w.Header().Set("Allow", "OPTIONS, PROPFIND, GET, HEAD")
	w.Header().Set("MS-Author-Via", "DAV")
	w.WriteHeader(http.StatusNoContent)
}

// handleRead 处理 GET/HEAD：
// 1. 先从缓存解析路径到文件项
// 2. HEAD 只返回元信息
// 3. GET 才向云盘申请真实下载链接并返回 302
func (s *Server) handleRead(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	entryPath := s.relativePath(r.URL.Path)
	entry, err := s.cache.Resolve(ctx, s.cloud, entryPath)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, ErrNotFound) {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}
	if entry.IsDir {
		http.Error(w, "directory is not downloadable", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodHead {
		writeFileMetadataHeaders(w, entry)
		w.WriteHeader(http.StatusOK)
		return
	}
	link, err := s.cloud.DirectLink(ctx, entry.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	headers := w.Header()
	headers.Del("Accept-Ranges")
	headers.Del("Content-Type")
	headers.Del("ETag")
	headers.Del("Last-Modified")
	w.Header().Set("Location", link)
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusFound)
}

// writeFileMetadataHeaders 把 Entry 转成下载响应头，供 GET/HEAD 共用。
func writeFileMetadataHeaders(w http.ResponseWriter, entry Entry) {
	prop := newProp(entry)
	headers := w.Header()
	headers.Set("Accept-Ranges", "none")
	headers.Set("Content-Type", prop.GetContentType)
	headers.Set("Content-Length", prop.GetContentLength)
	headers.Set("ETag", prop.GetETag)
	headers.Set("Last-Modified", prop.GetLastModified)
}

// mimeType 根据扩展名推断 MIME，未知类型时回退为二进制流。
func mimeType(name string) string {
	if typ := mime.TypeByExtension(path.Ext(name)); typ != "" {
		return typ
	}
	return "application/octet-stream"
}

// handlePropfind 处理目录浏览请求。
// Depth=0 返回当前项，Depth=1 会额外展开一级子目录内容。
func (s *Server) handlePropfind(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	entryPath := s.relativePath(r.URL.Path)
	entry, err := s.cache.Resolve(ctx, s.cloud, entryPath)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, ErrNotFound) {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}

	depth := 0
	if h := r.Header.Get("Depth"); h == "1" {
		depth = 1
	}

	responses := []Response{{Href: s.href(entryPath), Propstat: []Propstat{s.propstat(entry)}}}
	if depth == 1 && entry.IsDir {
		children, err := s.cache.List(ctx, s.cloud, entryPath, entry.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		for _, child := range children {
			childPath := path.Join(entryPath, child.Name)
			if childPath == "" {
				childPath = "/"
			}
			responses = append(responses, Response{
				Href:     s.href(childPath),
				Propstat: []Propstat{s.propstat(child)},
			})
		}
	}

	w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
	w.WriteHeader(http.StatusMultiStatus)
	if err := xml.NewEncoder(w).Encode(MultiStatus{
		XMLNS:     "DAV:",
		Responses: responses,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// href 把内部路径编码成 WebDAV 响应里的 Href。
func (s *Server) href(entryPath string) string {
	parts := strings.Split(strings.TrimPrefix(entryPath, "/"), "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	escaped := strings.Join(parts, "/")
	full := s.dav
	if escaped != "" {
		full += "/" + escaped
	}
	if strings.HasSuffix(entryPath, "/") || entryPath == "/" {
		full += "/"
	}
	return full
}

// propstat 为单个目录项构造 WebDAV 200 OK 属性块。
func (s *Server) propstat(entry Entry) Propstat {
	return Propstat{
		Prop:   newProp(entry),
		Status: "HTTP/1.1 200 OK",
	}
}

// newProp 将内部 Entry 映射成 WebDAV 属性结构。
func newProp(entry Entry) Prop {
	mod := entry.ModifiedAt
	if mod.IsZero() {
		mod = time.Now()
	}
	create := entry.CreatedAt
	if create.IsZero() {
		create = mod
	}
	prop := Prop{
		DisplayName:     entry.Name,
		GetLastModified: mod.UTC().Format(http.TimeFormat),
		CreationDate:    create.UTC().Format(time.RFC3339),
		GetETag:         fmt.Sprintf(`"%s-%d-%d"`, entry.ID, entry.Size, mod.Unix()),
	}
	if entry.IsDir {
		prop.ResourceType = &ResourceType{Collection: &struct{}{}}
		prop.GetContentType = "httpd/unix-directory"
		prop.GetContentLength = "0"
	} else {
		prop.ResourceType = &ResourceType{}
		prop.GetContentType = mimeType(entry.Name)
		prop.GetContentLength = strconv.FormatInt(entry.Size, 10)
	}
	return prop
}
