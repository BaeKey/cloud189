package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ---------- 日志等级系统 ----------

// LogLevel 日志等级：0=ERROR, 1=WARN, 2=INFO, 3=DEBUG
type LogLevel int

const (
	LogError LogLevel = iota
	LogWarn
	LogInfo
	LogDebug
)

var currentLogLevel = LogInfo // 默认 INFO

func parseLogLevel(s string) LogLevel {
	switch strings.ToLower(s) {
	case "error":
		return LogError
	case "warn", "warning":
		return LogWarn
	case "info":
		return LogInfo
	case "debug":
		return LogDebug
	default:
		return LogInfo
	}
}

func logLevelName(l LogLevel) string {
	switch l {
	case LogError:
		return "ERROR"
	case LogWarn:
		return "WARN"
	case LogInfo:
		return "INFO"
	case LogDebug:
		return "DEBUG"
	default:
		return "UNKNOWN"
	}
}

// logf 按等级输出日志。只有 msgLevel <= currentLogLevel 时才输出。
func logf(msgLevel LogLevel, format string, args ...any) {
	if msgLevel <= currentLogLevel {
		log.Printf(format, args...)
	}
}

// 便捷函数
func logError(format string, args ...any) { logf(LogError, format, args...) }
func logWarn(format string, args ...any)  { logf(LogWarn, format, args...) }
func logInfo(format string, args ...any)  { logf(LogInfo, format, args...) }
func logDebug(format string, args ...any) { logf(LogDebug, format, args...) }

// ---------- 配置结构 ----------

type Config struct {
	Server    ServerConfig    `json:"server"`
	Cloud189  Cloud189Config  `json:"cloud189"`
	Cache     CacheConfig     `json:"cache"`
	RateLimit RateLimitConfig `json:"rate_limit"`
	Security  SecurityConfig  `json:"security"`
	Log       LogConfig       `json:"log"`
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

// CacheConfig 描述目录和路径缓存的 TTL。
type CacheConfig struct {
	DirTTL   int `json:"dir_ttl_seconds"`   // 目录列表缓存秒数，默认 60
	EntryTTL int `json:"entry_ttl_seconds"` // 路径全量缓存秒数，默认 300
}

// RateLimitConfig 描述 API 限流参数。
type RateLimitConfig struct {
	Rate  int `json:"rate"`  // 每秒请求数，默认 5
	Burst int `json:"burst"` // 突发请求数，默认 10
}

// SecurityConfig 描述 root 启动后的降权目标。
type SecurityConfig struct {
	RunAsUID int `json:"run_as_uid"`
	RunAsGID int `json:"run_as_gid"`
}

// LogConfig 描述日志输出策略。
type LogConfig struct {
	Level   string `json:"level"`    // 日志等级：error/warn/info/debug，默认 info
	File    string `json:"file"`     // 日志文件路径，为空则只输出到 stderr
	MaxSize int64  `json:"max_size"` // 单个日志文件最大字节数，默认 10MB
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

// ---------- main ----------

func main() {
	cfg, configPath, statePath, err := LoadConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// 设置日志等级
	currentLogLevel = parseLogLevel(cfg.Log.Level)

	// 初始化日志输出（文件轮转）
	if err := initLogger(cfg.Log); err != nil {
		log.Fatalf("init logger: %v", err)
	}

	client, err := NewCloud189Client(cfg.Cloud189, statePath, cfg.RateLimit.Rate, cfg.RateLimit.Burst)
	if err != nil {
		log.Fatalf("init cloud189 client: %v", err)
	}

	dirTTL := time.Duration(cfg.Cache.DirTTL) * time.Second
	entryTTL := time.Duration(cfg.Cache.EntryTTL) * time.Second
	davPath := cleanBasePath(cfg.Server.BasePath)
	srv := &Server{
		dav:   davPath,
		cloud: client,
		cache: NewPathCache(dirTTL, entryTTL),
	}

	logInfo("[main] config: %s", configPath)
	logInfo("[main] webdav: %s", publicDAVURL(cfg.Server.Listen, davPath))
	logInfo("[main] cloud189 type: %s", cfg.Cloud189.Type)
	logInfo("[main] cache: dir_ttl=%v entry_ttl=%v", dirTTL, entryTTL)
	logInfo("[main] rate_limit: %d/s burst=%d", cfg.RateLimit.Rate, cfg.RateLimit.Burst)
	logInfo("[main] log_level: %s", logLevelName(currentLogLevel))

	httpServer := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve http: %v", err)
		}
	}()

	if err := maybeDropPrivileges(cfg.Security); err != nil {
		log.Fatalf("drop privileges: %v", err)
	}

	// 优雅关闭
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	logInfo("[main] received %s, shutting down...", sig)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logError("[main] server shutdown error: %v", err)
	}
	logInfo("[main] server stopped")
}

// ---------- 日志初始化 ----------

func initLogger(cfg LogConfig) error {
	if cfg.File == "" {
		return nil
	}
	maxSize := cfg.MaxSize
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024
	}
	w, err := NewRotatingLogWriter(cfg.File, maxSize)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", cfg.File, err)
	}
	log.SetOutput(w)
	logInfo("[main] logging to %s (max_size=%dMB)", cfg.File, maxSize/1024/1024)
	return nil
}

// RotatingLogWriter 实现基于文件大小的日志轮转。
// 超过 maxSize 时，当前文件重命名为 .old（覆盖旧备份），然后创建新文件。
// 只保留一个 .old 备份，不会日积月累过多。
type RotatingLogWriter struct {
	file    string
	maxSize int64
	fp      *os.File
}

func NewRotatingLogWriter(file string, maxSize int64) (*RotatingLogWriter, error) {
	fp, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	return &RotatingLogWriter{file: file, maxSize: maxSize, fp: fp}, nil
}

func (w *RotatingLogWriter) Write(p []byte) (int, error) {
	n, err := w.fp.Write(p)
	if err != nil {
		return n, err
	}
	info, err := w.fp.Stat()
	if err != nil {
		return n, nil
	}
	if info.Size() >= w.maxSize {
		w.rotate()
	}
	return n, nil
}

func (w *RotatingLogWriter) rotate() {
	w.fp.Close()
	_ = os.Rename(w.file, w.file+".old")
	fp, err := os.OpenFile(w.file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		log.SetOutput(os.Stderr)
		logError("[main] log rotation failed: %v", err)
		return
	}
	w.fp = fp
}

var _ io.Writer = (*RotatingLogWriter)(nil)

// ---------- 配置加载 ----------

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
	if cfg.Cache.DirTTL <= 0 {
		cfg.Cache.DirTTL = 60
	}
	if cfg.Cache.EntryTTL <= 0 {
		cfg.Cache.EntryTTL = 300
	}
	if cfg.RateLimit.Rate <= 0 {
		cfg.RateLimit.Rate = defaultRateLimit
	}
	if cfg.RateLimit.Burst <= 0 {
		cfg.RateLimit.Burst = defaultRateBurst
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}
	if cfg.Log.MaxSize <= 0 {
		cfg.Log.MaxSize = 10 * 1024 * 1024
	}

	// 迁移旧版 refresh token
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
		Cache: CacheConfig{
			DirTTL:   60,
			EntryTTL: 300,
		},
		RateLimit: RateLimitConfig{
			Rate:  defaultRateLimit,
			Burst: defaultRateBurst,
		},
		Security: SecurityConfig{
			RunAsUID: 65534,
			RunAsGID: 65534,
		},
		Log: LogConfig{
			Level:   "info",
			MaxSize: 10 * 1024 * 1024,
		},
	}
}

// ---------- 降权 ----------

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
	logInfo("[main] privileges dropped to uid=%d gid=%d", os.Geteuid(), os.Getegid())
	return nil
}

func nobodyUIDGID() (int, int) {
	return 65534, 65534
}

// ---------- 通用 JSON 读写 ----------

func ReadJSON(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func WriteJSON(path string, in any) error {
	data, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

// ---------- 路径工具 ----------

func cleanBasePath(p string) string {
	if p == "" || p == "/" {
		return "/dav"
	}
	return path.Clean("/" + p)
}

func publicDAVURL(listenAddr, basePath string) string {
	host := listenAddr
	if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}
	return "http://" + host + cleanBasePath(basePath)
}

// ---------- HTTP 路由 ----------

// routes 是整个 HTTP 服务的入口分发器，只暴露只读 WebDAV 能力 + 健康检查。
func (s *Server) routes() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 健康检查端点（不在 /dav 前缀下）
		if r.URL.Path == "/health" {
			s.handleHealth(w, r)
			return
		}
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

// handleHealth 处理健康检查请求。
// GET /health           → 返回服务状态和缓存统计
// GET /health?invalidate=1 → 清空缓存，立即感知上游变更
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 支持清空缓存
	if r.URL.Query().Get("invalidate") == "1" {
		s.cache.Invalidate()
	}

	entries, dirs := s.cache.Stats()
	result := map[string]any{
		"status":      "ok",
		"cache_entries": entries,
		"cache_dirs":    dirs,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

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

func (s *Server) handleOptions(w http.ResponseWriter) {
	w.Header().Set("DAV", "1")
	w.Header().Set("Allow", "OPTIONS, PROPFIND, GET, HEAD")
	w.Header().Set("MS-Author-Via", "DAV")
	w.WriteHeader(http.StatusNoContent)
}

// handleRead 处理 GET/HEAD。
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
		logError("[webdav] direct link failed: path=%s id=%s err=%v", entryPath, entry.ID, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	logDebug("[webdav] redirect: path=%s → %s", entryPath, truncateURL(link, 80))
	headers := w.Header()
	headers.Del("Accept-Ranges")
	headers.Del("Content-Type")
	headers.Del("ETag")
	headers.Del("Last-Modified")
	w.Header().Set("Location", link)
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusFound)
}

func truncateURL(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func writeFileMetadataHeaders(w http.ResponseWriter, entry Entry) {
	prop := newProp(entry)
	headers := w.Header()
	headers.Set("Accept-Ranges", "none")
	headers.Set("Content-Type", prop.GetContentType)
	headers.Set("Content-Length", prop.GetContentLength)
	headers.Set("ETag", prop.GetETag)
	headers.Set("Last-Modified", prop.GetLastModified)
}

func mimeType(name string) string {
	if typ := mime.TypeByExtension(path.Ext(name)); typ != "" {
		return typ
	}
	return "application/octet-stream"
}

// handlePropfind 处理目录浏览请求。
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

func (s *Server) propstat(entry Entry) Propstat {
	return Propstat{
		Prop:   newProp(entry),
		Status: "HTTP/1.1 200 OK",
	}
}

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
