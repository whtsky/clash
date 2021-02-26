package cachefile

import (
	"bytes"
	"encoding/gob"
	"io/ioutil"
	"os"
	"sync"

	"github.com/whtsky/clash/component/profile"
	C "github.com/whtsky/clash/constant"
	"github.com/whtsky/clash/log"
)

var (
	initOnce     sync.Once
	fileMode     os.FileMode = 0666
	defaultCache *CacheFile
)

type cache struct {
	Selected map[C.AdapterName]C.AdapterName
}

// CacheFile store and update the cache file
type CacheFile struct {
	path  string
	model *cache
	buf   *bytes.Buffer
	mux   sync.Mutex
}

func (c *CacheFile) SetSelected(group, selected C.AdapterName) {
	if !profile.StoreSelected.Load() {
		return
	}

	c.mux.Lock()
	defer c.mux.Unlock()

	model := c.element()

	model.Selected[group] = selected
	c.buf.Reset()
	if err := gob.NewEncoder(c.buf).Encode(model); err != nil {
		log.Warnln("[CacheFile] encode gob failed: %s", err.Error())
		return
	}

	if err := ioutil.WriteFile(c.path, c.buf.Bytes(), fileMode); err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.path, err.Error())
		return
	}
}

func (c *CacheFile) SelectedMap() map[C.AdapterName]C.AdapterName {
	if !profile.StoreSelected.Load() {
		return nil
	}

	c.mux.Lock()
	defer c.mux.Unlock()

	model := c.element()

	mapping := map[C.AdapterName]C.AdapterName{}
	for k, v := range model.Selected {
		mapping[k] = v
	}
	return mapping
}

func (c *CacheFile) element() *cache {
	if c.model != nil {
		return c.model
	}

	model := &cache{
		Selected: map[C.AdapterName]C.AdapterName{},
	}

	if buf, err := ioutil.ReadFile(c.path); err == nil {
		bufReader := bytes.NewBuffer(buf)
		gob.NewDecoder(bufReader).Decode(model)
	}

	c.model = model
	return c.model
}

// Cache return singleton of CacheFile
func Cache() *CacheFile {
	initOnce.Do(func() {
		defaultCache = &CacheFile{
			path: C.Path.Cache(),
			buf:  &bytes.Buffer{},
		}
	})

	return defaultCache
}
