/*
 * JuiceFS, Copyright 2020 Juicedata, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fuse

import (
	"context"
	"sync"
	"syscall"
	"time"

	"github.com/juicedata/juicefs/pkg/meta"
	"github.com/juicedata/juicefs/pkg/vfs"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// Ino is an alias to meta.Ino
type Ino = meta.Ino

// Attr is an alias to meta.Attr
type Attr = meta.Attr

// Context is an alias to vfs.LogContext
type Context = vfs.LogContext

type fuseContext struct {
	context.Context
	start    time.Time
	header   *fuse.InHeader
	canceled bool
	cancel   <-chan struct{}

	checkPermission bool
	sudoDenied      bool // sudo (UID=0) denied because caller is not a Kerberos admin
}

var gidcache = newGidCache(time.Minute * 5)
var krbcache *kerberosCache

var contextPool = sync.Pool{
	New: func() interface{} {
		return &fuseContext{}
	},
}

func (fs *fileSystem) newContext(cancel <-chan struct{}, header *fuse.InHeader) *fuseContext {
	ctx := contextPool.Get().(*fuseContext)
	ctx.Context = context.Background()
	ctx.start = time.Now()
	ctx.canceled = false
	ctx.cancel = cancel
	ctx.header = header
	ctx.sudoDenied = false
	ctx.checkPermission = fs.conf.NonDefaultPermission && header.Uid != 0
	if header.Uid == 0 && fs.conf.RootSquash != nil {
		ctx.checkPermission = true
		ctx.header.Uid = fs.conf.RootSquash.Uid
		ctx.header.Gid = fs.conf.RootSquash.Gid
	}
	if fs.conf.AllSquash != nil {
		ctx.checkPermission = true
		ctx.header.Uid = fs.conf.AllSquash.Uid
		ctx.header.Gid = fs.conf.AllSquash.Gid
	}

	// KerberosSquash: deny all sudo (UID=0) operations by default.
	// Only members of the Kerberos admin GID are granted root-equivalent access.
	// Non-sudo (UID≠0) operations skip Kerberos/LDAP lookup entirely.
	if fs.conf.KerberosSquash != nil && krbcache != nil && header.Uid == 0 {
		adminGid := fs.conf.KerberosSquash.AdminGid
		if adminGid == 0 {
			// AdminGid not configured — cannot determine admin status; deny all sudo
			logger.Warnf("kerberos: DENIED sudo pid=%d (admin_gid not configured)", header.Pid)
			ctx.sudoDenied = true
		} else {
			krbStart := time.Now()
			lookupUid := header.Uid

			if realUid, err := getProcRealUID(header.Pid); err == nil {
				lookupUid = realUid
				logger.Debugf("kerberos: pid=%d uid=0→realuid=%d (proc lookup)",
					header.Pid, realUid)
			} else {
				logger.Warnf("kerberos: pid=%d uid=0 proc lookup failed: %v",
					header.Pid, err)
			}

			valid, _, _, ldapGids, cacheHit := krbcache.validateWithMeta(lookupUid)
			krbElapsed := time.Since(krbStart)

			isAdmin := false
			if valid {
				for _, gid := range ldapGids {
					if gid == adminGid {
						isAdmin = true
						break
					}
				}
			}

			if isAdmin {
				logger.Infof("kerberos: uid=%d→ADMIN (member of gid=%d) cache=%v elapsed=%v",
					lookupUid, adminGid, cacheHit, krbElapsed)
				ctx.checkPermission = false
				ctx.header.Uid = 0
				ctx.header.Gid = 0
			} else {
				logger.Warnf("kerberos: DENIED sudo uid=%d pid=%d admin=false cache=%v elapsed=%v",
					lookupUid, header.Pid, cacheHit, krbElapsed)
				ctx.sudoDenied = true
			}
		}
	}

	return ctx
}

func releaseContext(ctx *fuseContext) {
	contextPool.Put(ctx)
}

func (c *fuseContext) Uid() uint32 {
	return c.header.Uid
}

func (c *fuseContext) Gid() uint32 {
	return c.header.Gid
}

func (c *fuseContext) Gids() []uint32 {
	if c.checkPermission {
		return gidcache.get(c.Pid(), c.Gid())
	}
	return []uint32{c.header.Gid}
}

func (c *fuseContext) Pid() uint32 {
	return c.header.Pid
}

func (c *fuseContext) Duration() time.Duration {
	return time.Since(c.start)
}

func (c *fuseContext) Cancel() {
	c.canceled = true
}

func (c *fuseContext) CheckPermission() bool {
	return c.checkPermission
}

func (c *fuseContext) SudoDenied() bool {
	return c.sudoDenied
}

func (c *fuseContext) Canceled() bool {
	if c.Duration() < time.Second {
		return false
	}
	if c.canceled {
		return true
	}
	select {
	case <-c.cancel:
		return true
	default:
		return false
	}
}

func (c *fuseContext) WithValue(k, v interface{}) meta.Context {
	wc := *c // gids is a const, so it's safe to shallow copy
	wc.Context = context.WithValue(c.Context, k, v)
	return &wc
}

func (c *fuseContext) Err() error {
	return syscall.EINTR
}

// func (c *fuseContext) Done() <-chan struct{} {
// 	return c.cancel
// }
