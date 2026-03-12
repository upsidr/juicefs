//go:build darwin
// +build darwin

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
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// checkTicketViaCLI checks for a valid Kerberos ticket using klist run as
// the target user. On macOS, Kerberos tickets are stored in the system's
// credential manager (API cache), not in /tmp/krb5cc_<uid>, so we must
// run klist in the user's context to access their tickets.
// Returns the principal (e.g., "admin@DIRECTORY.UPSIDR.LOCAL") or empty string.
func checkTicketViaCLI(uid uint32) string {
	cmd := exec.Command("klist")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: uid},
	}
	out, err := cmd.Output()
	if err != nil {
		logger.Debugf("kerberos: klist as uid=%d failed: %v", uid, err)
		return ""
	}

	// Parse "Principal: admin@DIRECTORY.UPSIDR.LOCAL" from klist output
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Principal:") {
			principal := strings.TrimSpace(strings.TrimPrefix(line, "Principal:"))
			if principal != "" && strings.Contains(principal, "@") {
				logger.Debugf("kerberos: klist found principal=%s for uid=%d", principal, uid)
				return principal
			}
		}
	}

	logger.Debugf("kerberos: klist as uid=%d returned no principal", uid)
	return ""
}

// lookupLDAPIdentity queries the LDAP directory node directly to resolve
// a username to its LDAP UID/GID/groups. Using a specific LDAP node
// (e.g., /LDAPv3/ipa.directory.upsidr.local) instead of /Search prevents
// local directory poisoning via dscl group injection.
func lookupLDAPIdentity(username string, ldapNode string) (uid, gid uint32, gids []uint32, ok bool) {
	node := ldapNode

	// Query for UniqueID (UID)
	out, err := exec.Command("dscl", node, "-read", "/Users/"+username, "UniqueID").Output()
	if err != nil {
		logger.Debugf("kerberos: dscl %s read UniqueID for %s failed: %v", node, username, err)
		return 0, 0, nil, false
	}
	uid = parseDsclMaxValue(string(out), "UniqueID")
	if uid == 0 {
		return 0, 0, nil, false
	}

	// Query for PrimaryGroupID (GID)
	out, err = exec.Command("dscl", node, "-read", "/Users/"+username, "PrimaryGroupID").Output()
	if err != nil {
		logger.Debugf("kerberos: dscl %s read PrimaryGroupID for %s failed: %v", node, username, err)
		return uid, uid, nil, true
	}
	gid = parseDsclMaxValue(string(out), "PrimaryGroupID")
	if gid == 0 {
		gid = uid
	}

	// Get group memberships
	gids = append(gids, gid)
	out, err = exec.Command("dscl", node, "-list", "/Groups", "PrimaryGroupID").Output()
	if err == nil {
		groupGids := parseDsclGroupList(string(out))
		for groupName, groupGid := range groupGids {
			if isMemberOfGroup(node, groupName, username) {
				if groupGid != gid {
					gids = append(gids, groupGid)
				}
			}
		}
	}

	return uid, gid, gids, true
}

// parseDsclMaxValue extracts the largest numeric value for a key from dscl output.
// When a local user shadows an LDAP user, dscl /Search returns multiple values:
//
//	UniqueID: 501
//	UniqueID: 60001
//
// We pick the largest (the LDAP UID), since local UIDs are typically < 1000.
func parseDsclMaxValue(output, key string) uint32 {
	var maxVal uint32
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		var val uint64
		var err error
		if strings.HasPrefix(line, key+":") {
			val, err = strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, key+":")), 10, 32)
		} else {
			val, err = strconv.ParseUint(line, 10, 32)
		}
		if err == nil && uint32(val) > maxVal {
			maxVal = uint32(val)
		}
	}
	return maxVal
}

// parseDsclGroupList parses "dscl <node> -list /Groups PrimaryGroupID" output.
func parseDsclGroupList(output string) map[string]uint32 {
	result := make(map[string]uint32)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			name := fields[0]
			if gid, err := strconv.ParseUint(fields[len(fields)-1], 10, 32); err == nil {
				result[name] = uint32(gid)
			}
		}
	}
	return result
}

// isMemberOfGroup checks if a user is a member of a group via dscl.
func isMemberOfGroup(node, groupName, username string) bool {
	out, err := exec.Command("dscl", node, "-read", "/Groups/"+groupName, "GroupMembership").Output()
	if err != nil {
		return false
	}
	for _, member := range strings.Fields(string(out)) {
		if member == username {
			return true
		}
	}
	return false
}
