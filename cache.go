package main

import (
	"context"
	"path"
	"strings"
	"sync"
	"time"
)

// PathCache 为天翼云盘目录结构提供两级缓存和并发去重。
//
// 两级缓存：
//   - entryCache: 路径 → 单个 Entry（文件或目录），TTL 较长（默认 5 分钟）
//   - dirCache:   目录路径 → 该目录下所有子项，TTL 较短（默认 1 分钟）
//
// entryCache 是"路径全量缓存"，深度路径只需一次查找，无需逐级遍历。
// dirCache  用于 PROPFIND Depth=1 场景，直接返回目录列表。
//
// 并发去重：同一路径的并发请求只触发一次真实 API 调用。
type PathCache struct {
	mu sync.RWMutex

	dirTTL   time.Duration // 目录列表缓存 TTL
	entryTTL time.Duration // 路径全量缓存 TTL

	entries map[string]cacheEntry  // 路径 → Entry（文件和目录都缓存）
	dirs    map[string]cacheDir    // 目录路径 → 目录下所有子项
	loading map[string]*dirLoadCall // 正在加载的目录（并发去重）
}

type cacheEntry struct {
	entry  Entry
	expire time.Time
}

// cacheDir 用于短时复用目录结果，同时保留同路径并发去重。
type cacheDir struct {
	items  []Entry
	byName map[string]Entry
	expire time.Time
}

// dirLoadCall 用于把同一路径的并发目录加载合并成一次真实请求。
type dirLoadCall struct {
	done chan struct{}
	dir  cacheDir
	err  error
}

// NewPathCache 创建目录请求去重器。
// dirTTL: 目录列表缓存时间（默认 60 秒）
// entryTTL: 路径全量缓存时间（默认 300 秒）
func NewPathCache(dirTTL, entryTTL time.Duration) *PathCache {
	if dirTTL <= 0 {
		dirTTL = 60 * time.Second
	}
	if entryTTL <= 0 {
		entryTTL = 300 * time.Second
	}
	return &PathCache{
		dirTTL:   dirTTL,
		entryTTL: entryTTL,
		entries:  map[string]cacheEntry{},
		dirs:     map[string]cacheDir{},
		loading:  map[string]*dirLoadCall{},
	}
}

// Resolve 将一个 WebDAV 路径解析到最终 Entry。
// 优先查 entryCache（路径全量缓存），命中则直接返回，无需逐级遍历。
// 未命中时逐级遍历，遍历过程中将每一级都写入 entryCache。
func (c *PathCache) Resolve(ctx context.Context, client *Cloud189Client, p string) (Entry, error) {
	p = cleanResolvePath(p)
	if p == "/" {
		return client.RootEntry(), nil
	}

	// 优先查路径全量缓存
	if entry, ok := c.getEntry(p); ok {
		return entry, nil
	}

	// 缓存未命中，逐级遍历
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	curPath := "/"
	cur := client.RootEntry()
	for _, part := range parts {
		children, err := c.listDir(ctx, client, curPath, cur.ID)
		if err != nil {
			return Entry{}, err
		}
		child, ok := children.byName[part]
		if !ok {
			return Entry{}, ErrNotFound
		}
		curPath = joinEntryPath(curPath, part)
		cur = child
		// 遍历过程中填充 entryCache，后续访问同路径或子路径可以快速命中
		c.setEntry(curPath, child)
	}
	return cur, nil
}

// List 返回目录下一级子项列表，优先命中缓存，其次做并发去重。
func (c *PathCache) List(ctx context.Context, client *Cloud189Client, dirPath string, dirID string) ([]Entry, error) {
	dir, err := c.listDir(ctx, client, dirPath, dirID)
	if err != nil {
		return nil, err
	}
	return cloneEntries(dir.items), nil
}

// listDir 是目录缓存的核心入口：
//  1. 先查目录缓存（dirTTL）
//  2. 未命中时看是否已有同路径目录请求在进行
//  3. 只让一个请求真的去访问云盘目录接口
//  4. 成功后将所有子项写入 entryCache（路径全量缓存）
func (c *PathCache) listDir(ctx context.Context, client *Cloud189Client, dirPath string, dirID string) (cacheDir, error) {
	dirPath = cleanResolvePath(dirPath)

	// 查目录缓存
	if dir, ok := c.getDir(dirPath); ok {
		return dir, nil
	}

	// 并发去重
	call, wait, ok := c.beginDirLoad(dirPath)
	if ok {
		select {
		case <-ctx.Done():
			return cacheDir{}, ctx.Err()
		case <-wait:
			return call.dir, call.err
		}
	}

	logDebug("[cache] miss dir=%s, loading from API", dirPath)
	items, err := client.List(ctx, dirID)
	if err != nil {
		c.finishDirLoad(dirPath, call, cacheDir{}, err)
		return cacheDir{}, err
	}

	loaded := newCacheDir(items, c.dirTTL)
	c.setDir(dirPath, loaded)

	// 将所有子项写入 entryCache（路径全量缓存），下次直接命中
	for _, item := range items {
		c.setEntry(joinEntryPath(dirPath, item.Name), item)
	}

	c.finishDirLoad(dirPath, call, loaded, nil)
	return loaded, nil
}

func (c *PathCache) getEntry(p string) (Entry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, ok := c.entries[p]
	if !ok || time.Now().After(item.expire) {
		return Entry{}, false
	}
	return item.entry, true
}

func (c *PathCache) setEntry(p string, entry Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[p] = cacheEntry{
		entry:  entry,
		expire: time.Now().Add(c.entryTTL),
	}
}

func (c *PathCache) getDir(p string) (cacheDir, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, ok := c.dirs[p]
	if !ok || time.Now().After(item.expire) {
		return cacheDir{}, false
	}
	return item, true
}

func (c *PathCache) setDir(p string, dir cacheDir) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dirs[p] = dir
}

// beginDirLoad 注册一次目录加载，若已有同路径加载在进行中则返回等待句柄。
func (c *PathCache) beginDirLoad(p string) (*dirLoadCall, <-chan struct{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if loading, ok := c.loading[p]; ok {
		return loading, loading.done, true
	}
	call := &dirLoadCall{done: make(chan struct{})}
	c.loading[p] = call
	return call, nil, false
}

// finishDirLoad 结束目录加载并唤醒等待同一路径结果的协程。
func (c *PathCache) finishDirLoad(p string, call *dirLoadCall, dir cacheDir, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	call.dir = dir
	call.err = err
	delete(c.loading, p)
	close(call.done)
}

// cleanResolvePath 把任意输入路径标准化成内部统一格式。
func cleanResolvePath(p string) string {
	if p == "" {
		return "/"
	}
	p = path.Clean("/" + strings.TrimPrefix(p, "/"))
	if p == "." {
		return "/"
	}
	return p
}

// newCacheDir 由目录列表构造临时索引结构，供短时间内的重复访问复用。
func newCacheDir(items []Entry, ttl time.Duration) cacheDir {
	cloned := cloneEntries(items)
	byName := make(map[string]Entry, len(cloned))
	for _, item := range cloned {
		byName[item.Name] = item
	}
	return cacheDir{
		items:  cloned,
		byName: byName,
		expire: time.Now().Add(ttl),
	}
}

// cloneEntries 复制目录项切片，避免缓存内部数据被外部修改。
func cloneEntries(items []Entry) []Entry {
	if len(items) == 0 {
		return nil
	}
	cloned := make([]Entry, len(items))
	copy(cloned, items)
	return cloned
}

// joinEntryPath 拼接父目录和子项名称。
func joinEntryPath(dirPath, name string) string {
	if dirPath == "/" {
		return "/" + name
	}
	return path.Join(dirPath, name)
}

// Invalidate 清空所有缓存，下次请求将重新从 API 拉取。
// 用于上游（天翼云盘）有变更时手动触发刷新。
func (c *PathCache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]cacheEntry{}
	c.dirs = map[string]cacheDir{}
	logInfo("[cache] invalidated all entries and dirs")
}

// Stats 返回当前缓存的条目数，供健康检查端点使用。
func (c *PathCache) Stats() (entries int, dirs int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries), len(c.dirs)
}
