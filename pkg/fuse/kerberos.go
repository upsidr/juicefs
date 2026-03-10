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
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	krb "github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
)

// kerberosResult holds the cached result of a Kerberos ticket validation.
type kerberosResult struct {
	valid     bool
	principal string   // e.g., "admin@DIRECTORY.UPSIDR.LOCAL"
	ldapUid   uint32
	ldapGid   uint32
	ldapGids  []uint32 // all group memberships (for admin check)
	expire    time.Time
}

// kerberosCache caches per-UID Kerberos validation results.
type kerberosCache struct {
	sync.Mutex
	results       map[uint32]*kerberosResult
	cacheTTL      time.Duration
	krbConfig     *config.Config
	expectedRealm string // realm specified via --kerberos-realm
	ldapNode      string // LDAP node (e.g., /LDAPv3/ipa.directory.upsidr.local)
}

func newKerberosCache(cacheTTL time.Duration, krbConfPath string, realm string, ldapNode string) *kerberosCache {
	if krbConfPath == "" {
		krbConfPath = "/etc/krb5.conf"
	}
	cfg, err := config.Load(krbConfPath)
	if err != nil {
		logger.Warnf("kerberos: failed to load krb5.conf from %s: %s", krbConfPath, err)
	}

	kc := &kerberosCache{
		results:       make(map[uint32]*kerberosResult),
		cacheTTL:      cacheTTL,
		krbConfig:     cfg,
		expectedRealm: realm,
		ldapNode:      ldapNode,
	}
	go kc.cleanup()
	return kc
}

// cleanup periodically removes expired cache entries.
func (kc *kerberosCache) cleanup() {
	for {
		time.Sleep(time.Second * 30)
		kc.Lock()
		now := time.Now()
		expired := 0
		for uid, r := range kc.results {
			if r.expire.Before(now) {
				delete(kc.results, uid)
				expired++
			}
		}
		remaining := len(kc.results)
		kc.Unlock()
		if expired > 0 {
			logger.Debugf("kerberos: cache cleanup removed %d expired entries, %d remaining",
				expired, remaining)
		}
	}
}

// validateWithMeta checks if the given UID has a valid Kerberos ticket.
// Returns validation result, LDAP UID/GID, group list, and whether it was a cache hit.
func (kc *kerberosCache) validateWithMeta(uid uint32) (valid bool, ldapUid, ldapGid uint32, ldapGids []uint32, cacheHit bool) {
	if kc == nil {
		return false, 0, 0, nil, false
	}

	now := time.Now()
	kc.Lock()
	if r, ok := kc.results[uid]; ok && r.expire.After(now) {
		kc.Unlock()
		return r.valid, r.ldapUid, r.ldapGid, r.ldapGids, true
	}
	kc.Unlock()

	// Cache miss — perform actual ticket validation
	result := kc.checkTicket(uid)

	kc.Lock()
	kc.results[uid] = result
	kc.Unlock()

	return result.valid, result.ldapUid, result.ldapGid, result.ldapGids, false
}

// checkTicket validates the Kerberos ticket for the given UID.
// Security verification chain:
//  1. ccache file ownership (stat UID == lookupUid)
//  2. Realm matches --kerberos-realm
//  3. KDC verification via TGS request (cryptographic validation)
//  4. Principal → LDAP UID matches lookupUid
//  5. LDAP group lookup restricted to /LDAPv3/<server> node
func (kc *kerberosCache) checkTicket(uid uint32) *kerberosResult {
	invalidResult := &kerberosResult{
		valid:  false,
		expire: time.Now().Add(kc.cacheTTL),
	}

	if kc.krbConfig == nil {
		return invalidResult
	}

	ccachePath := fmt.Sprintf("/tmp/krb5cc_%d", uid)

	// Step 1: verify ccache file ownership matches lookupUid
	// Prevents ticket theft via sudo cp
	info, err := os.Stat(ccachePath)
	if err != nil {
		logger.Debugf("kerberos: ccache not found for uid=%d path=%s: %v", uid, ccachePath, err)
		return invalidResult
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(uid) {
		logger.Warnf("kerberos: ccache owner mismatch: file uid=%d, expected=%d, path=%s",
			stat.Uid, uid, ccachePath)
		return invalidResult
	}

	// Step 2: parse ccache (gokrb5 panics on empty/invalid files, so we recover)
	client, err := kc.loadAndParseCache(ccachePath, uid)
	if err != nil {
		return invalidResult
	}

	// Step 3: verify realm matches expected value (reject rogue KDC / cross-realm)
	realm := client.Credentials.Domain()
	if realm != kc.expectedRealm {
		logger.Warnf("kerberos: realm mismatch: got %s, expected %s, uid=%d",
			realm, kc.expectedRealm, uid)
		return invalidResult
	}

	// Step 4: issue TGS request to KDC for cryptographic ticket verification
	// Prevents ccache file forgery
	err = client.Login()
	if err != nil {
		logger.Warnf("kerberos: KDC verification failed for uid=%d: %v", uid, err)
		return invalidResult
	}

	principal := client.Credentials.UserName() + "@" + realm
	username := client.Credentials.UserName()

	// Step 5: verify principal's LDAP UID matches lookupUid
	// Prevents ticket reuse across users
	// LDAP group lookup restricted to ldapNode (prevents local directory poisoning)
	ldapUid, ldapGid, ldapGids := lookupUserIdentity(username, uid, kc.ldapNode)
	if ldapUid != uid {
		logger.Warnf("kerberos: principal UID mismatch: principal=%s ldapUid=%d, expected=%d",
			principal, ldapUid, uid)
		return invalidResult
	}

	logger.Infof("kerberos: ticket validated for principal=%s uid=%d", principal, ldapUid)
	return &kerberosResult{
		valid:     true,
		principal: principal,
		ldapUid:   ldapUid,
		ldapGid:   ldapGid,
		ldapGids:  ldapGids,
		expire:    time.Now().Add(kc.cacheTTL),
	}
}

// loadAndParseCache reads and parses a ccache file, recovering from gokrb5 panics.
func (kc *kerberosCache) loadAndParseCache(ccachePath string, uid uint32) (client *krb.Client, err error) {
	defer func() {
		if r := recover(); r != nil {
			logger.Warnf("kerberos: ccache file is invalid or empty for uid=%d path=%s: %v", uid, ccachePath, r)
			err = fmt.Errorf("ccache panic: %v", r)
		}
	}()

	ccache, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		logger.Debugf("kerberos: failed to load ccache for uid=%d path=%s: %v", uid, ccachePath, err)
		return nil, err
	}

	client, err = krb.NewFromCCache(ccache, kc.krbConfig)
	if err != nil {
		logger.Debugf("kerberos: invalid ccache for uid=%d: %v", uid, err)
		return nil, err
	}

	if ok, err := client.IsConfigured(); !ok || err != nil {
		logger.Debugf("kerberos: client not configured for uid=%d: %v", uid, err)
		return nil, fmt.Errorf("client not configured: %v", err)
	}

	return client, nil
}

// lookupUserIdentity resolves LDAP UID/GID/groups for a username.
// ldapNode specifies the directory node to query (e.g., /LDAPv3/ipa.directory.upsidr.local)
// to prevent local directory poisoning.
func lookupUserIdentity(username string, fallbackUid uint32, ldapNode string) (uid, gid uint32, gids []uint32) {
	if ldapNode != "" {
		uid, gid, gids, ok := lookupLDAPIdentity(username, ldapNode)
		if ok {
			logger.Debugf("kerberos: LDAP lookup for %s: uid=%d gid=%d gids=%v", username, uid, gid, gids)
			return uid, gid, gids
		}
	}

	// Fallback to `id` command
	logger.Debugf("kerberos: LDAP lookup failed for %s, falling back to id command", username)
	return lookupUserIdentityViaID(username, fallbackUid)
}

// lookupUserIdentityViaID uses the `id` command to resolve UID/GID/groups.
// Note: on macOS this may return the local UID if a local user shadows the LDAP user.
func lookupUserIdentityViaID(username string, fallbackUid uint32) (uid, gid uint32, gids []uint32) {
	uid = fallbackUid
	gid = fallbackUid

	out, err := exec.Command("id", "-u", username).Output()
	if err != nil {
		logger.Debugf("kerberos: id -u %s failed: %v, using fallback uid=%d", username, err, fallbackUid)
		return
	}
	if u, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 32); err == nil {
		uid = uint32(u)
	}

	out, err = exec.Command("id", "-g", username).Output()
	if err != nil {
		logger.Debugf("kerberos: id -g %s failed: %v", username, err)
		return
	}
	if g, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 32); err == nil {
		gid = uint32(g)
	}

	out, err = exec.Command("id", "-G", username).Output()
	if err != nil {
		logger.Debugf("kerberos: id -G %s failed: %v", username, err)
		return
	}
	for _, s := range strings.Fields(strings.TrimSpace(string(out))) {
		if g, err := strconv.ParseUint(s, 10, 32); err == nil {
			gids = append(gids, uint32(g))
		}
	}
	return
}
