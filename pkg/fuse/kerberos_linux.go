//go:build linux
// +build linux

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
	"strconv"
	"strings"
)

// getProcRealUID returns the real UID of the process identified by pid.
// On Linux, reads /proc/<pid>/status to find the Uid line.
func getProcRealUID(pid uint32) (uint32, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, fmt.Errorf("read /proc/%d/status: %w", pid, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uid, err := strconv.ParseUint(fields[1], 10, 32)
				if err != nil {
					return 0, fmt.Errorf("parse uid from /proc/%d/status: %w", pid, err)
				}
				return uint32(uid), nil
			}
		}
	}
	return 0, fmt.Errorf("uid not found in /proc/%d/status", pid)
}

// checkTicketViaCLI is the Linux fallback. On Linux, file-based credential
// caches (/tmp/krb5cc_<uid>) are the default, so the file-based check
// in checkTicket() should work. This is only called if that fails.
func checkTicketViaCLI(uid uint32) string {
	// On Linux, file-based caches are the norm. If the file-based check
	// already failed, there's likely no valid ticket.
	return ""
}

// lookupLDAPIdentity is a stub on Linux. On Linux, SSSD/nss_ldap typically
// ensures that `id <username>` returns the correct LDAP UID/GID, so the
// fallback to `id` in lookupUserIdentityViaID is sufficient.
func lookupLDAPIdentity(username string, ldapNode string) (uid, gid uint32, gids []uint32, ok bool) {
	return 0, 0, nil, false
}
