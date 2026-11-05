package api

import (
	"strings"
	"time"

	"github.com/philippe/hauswart/internal/sign"
)

func init() {
	for _, taskType := range []string{TaskPkgInstall, TaskPkgRemove, TaskFlatpakInstall} {
		register(taskType, false, checkPackages)
	}
	// Updates come from the device's own repositories, so a signature would
	// only delay security fixes.
	register(TaskPkgUpgrade, true, func(struct{}) error { return nil })
	register(TaskFilePut, false, checkFilePut)
	register(TaskCAInstall, false, checkCAInstall)
	register(TaskSudoGrant, false, checkSudoGrant)
	// Revoking only ever takes rights away.
	register(TaskSudoRevoke, true, checkUser)
	register(TaskUserLock, false, checkUser)
	register(TaskUserUnlock, false, checkUser)
	register(TaskUserPassword, false, checkPassword)
	register(TaskUserCreate, false, checkUserCreate)
	register(TaskKeysSet, false, checkKeys)
	register(TaskLimitSet, false, checkLimit)
}

func checkPackages(p PackagesPayload) error {
	if len(p.Packages) == 0 {
		return Fail(ErrNoPackages)
	}
	for _, name := range p.Packages {
		if !ValidPackage(name) {
			return Fail(ErrInvalidPackage, name)
		}
	}
	return nil
}

func checkFilePut(p FilePutPayload) error {
	if !strings.HasPrefix(p.Path, "/") || strings.Contains(p.Path, "..") || hasControl(p.Path) {
		return Fail(ErrInvalidPath, p.Path)
	}
	if p.Mode != "" && !modeRe.MatchString(p.Mode) {
		return Fail(ErrInvalidMode, p.Mode)
	}
	return nil
}

func checkCAInstall(p CAInstallPayload) error {
	if !caNameRe.MatchString(p.Name) {
		return Fail(ErrInvalidCAName, p.Name)
	}
	if !singleCertificate(p.PEM) {
		return Fail(ErrNotPEM)
	}
	return nil
}

func checkSudoGrant(p SudoGrantPayload) error {
	if !ValidUser(p.User) {
		return Fail(ErrInvalidUser, p.User)
	}
	if p.ExpiresAt.IsZero() {
		return Fail(ErrSudoNoExpiry)
	}
	if time.Until(p.ExpiresAt) > MaxGrant {
		return Fail(ErrSudoTooLong, MaxGrant.String())
	}
	for _, c := range p.Commands {
		if !commandRe.MatchString(c) || strings.Contains(c, "..") {
			return Fail(ErrInvalidCommand, c)
		}
	}
	return nil
}

func checkUser(p UserPayload) error {
	if !ValidUser(p.User) {
		return Fail(ErrInvalidUser, p.User)
	}
	return nil
}

func checkPassword(p PasswordPayload) error {
	if !ValidUser(p.User) {
		return Fail(ErrInvalidUser, p.User)
	}
	if !hashRe.MatchString(p.Hash) {
		return Fail(ErrInvalidHash)
	}
	return nil
}

func checkUserCreate(p UserPayload) error {
	if !ValidUser(p.User) {
		return Fail(ErrInvalidUser, p.User)
	}
	if strings.Contains(p.FullName, ":") || hasControl(p.FullName) {
		return Fail(ErrInvalidFullName)
	}
	for _, g := range p.Groups {
		// Membership in these equals root, so it must go through the
		// time-limited sudo grant instead.
		if !userRe.MatchString(g) || privilegedGroups[g] {
			return Fail(ErrGroupNotAllowed, g)
		}
	}
	return nil
}

func checkKeys(p KeysPayload) error {
	if len(p.Keys) == 0 {
		return Fail(ErrInvalidKeys)
	}
	for _, key := range p.Keys {
		if _, err := sign.ParseKey(key); err != nil {
			return Fail(ErrInvalidKeys)
		}
	}
	return nil
}

func checkLimit(p LimitPayload) error {
	if !ValidUser(p.User) {
		return Fail(ErrInvalidUser, p.User)
	}
	if p.CPUPercent < 0 || p.MemoryMB < 0 {
		return Fail(ErrNegativeLimit)
	}
	if p.CPUPercent == 0 && p.MemoryMB == 0 {
		return Fail(ErrNoLimit)
	}
	return nil
}
