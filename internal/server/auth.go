package server

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/philippe/hauswart/internal/api"
	"github.com/philippe/hauswart/internal/store"
)

func init() {
	addRoutes(func(s *Server, mux *http.ServeMux) {
		mux.HandleFunc("POST /api/login", s.handleLogin)
		mux.Handle("POST /api/logout", s.user(s.handleLogout))
		mux.Handle("GET /api/me", s.user(s.handleMe))
		mux.Handle("POST /api/password", s.user(s.handleChangePassword))
	})
}

// --- auth wrappers ---

type userHandler func(http.ResponseWriter, *http.Request, store.User)

func (s *Server) user(next userHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Browsers cannot attach a custom header to a cross-site form post,
		// so this backs up the SameSite cookie against CSRF.
		if r.Method != http.MethodGet && r.Header.Get("X-Hauswart") != "1" {
			fail(w, http.StatusForbidden, api.ErrMissingHeader)
			return
		}
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			fail(w, http.StatusUnauthorized, api.ErrNotLoggedIn)
			return
		}
		u, err := s.store.SessionUser(r.Context(), c.Value)
		if errors.Is(err, store.ErrNotFound) {
			fail(w, http.StatusUnauthorized, api.ErrNotLoggedIn)
			return
		}
		if err != nil {
			s.internal(w, err)
			return
		}
		next(w, r, u)
	})
}

func (s *Server) admin(next userHandler) http.Handler {
	return s.user(func(w http.ResponseWriter, r *http.Request, u store.User) {
		if u.Role != "admin" {
			fail(w, http.StatusForbidden, api.ErrAdminOnly)
			return
		}
		next(w, r, u)
	})
}

// approver lets through those who may approve: admins and parents.
func (s *Server) approver(next userHandler) http.Handler {
	return s.user(func(w http.ResponseWriter, r *http.Request, u store.User) {
		if u.Role != store.RoleAdmin && u.Role != store.RoleParent {
			fail(w, http.StatusForbidden, api.ErrApproverOnly)
			return
		}
		next(w, r, u)
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	ip := clientIP(r)
	if s.lockedOut(ip) {
		fail(w, http.StatusTooManyRequests, api.ErrTooManyAttempts)
		return
	}
	u, err := s.store.UserByName(r.Context(), in.Username)
	hash := s.dummyHash
	if err == nil {
		hash = []byte(u.PasswordHash())
	} else if !errors.Is(err, store.ErrNotFound) {
		s.internal(w, err)
		return
	}
	cmpErr := bcrypt.CompareHashAndPassword(hash, []byte(in.Password))
	if err != nil || cmpErr != nil {
		s.recordFailure(ip)
		s.audit(r, in.Username, "login.failed", ip)
		fail(w, http.StatusUnauthorized, api.ErrWrongCredentials)
		return
	}
	s.clearFailures(ip)
	token, err := s.store.CreateSession(r.Context(), u.ID, sessionTTL)
	if err != nil {
		s.internal(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", MaxAge: int(sessionTTL.Seconds()),
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
	s.audit(r, u.Username, "login", ip)
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) lockedOut(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.failures[ip]
	if f == nil {
		return false
	}
	if f.count >= maxLoginFails && time.Now().Before(f.until) {
		return true
	}
	if time.Now().After(f.until) {
		delete(s.failures, ip)
	}
	return false
}

func (s *Server) recordFailure(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.failures[ip]
	if f == nil {
		f = &loginFailure{}
		s.failures[ip] = f
	}
	f.count++
	f.until = time.Now().Add(loginLockout)
}

func (s *Server) clearFailures(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.failures, ip)
}

// --- session ---

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, _ store.User) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if err := s.store.DeleteSession(r.Context(), c.Value); err != nil {
			s.internal(w, err)
			return
		}
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, _ *http.Request, u store.User) {
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	ip := clientIP(r)
	if s.lockedOut(ip) {
		fail(w, http.StatusTooManyRequests, api.ErrTooManyAttempts)
		return
	}
	current, err := s.store.UserPasswordHash(r.Context(), u.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(current), []byte(in.Current)) != nil {
		s.recordFailure(ip)
		s.audit(r, u.Username, "password.change_failed", ip)
		fail(w, http.StatusForbidden, api.ErrWrongPassword)
		return
	}
	if len(in.New) < minPasswordLen {
		fail(w, http.StatusBadRequest, api.ErrPasswordTooShort, strconv.Itoa(minPasswordLen))
		return
	}
	hash, err := HashPassword(in.New)
	if err != nil {
		fail(w, http.StatusBadRequest, api.ErrPasswordTooLong)
		return
	}
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		s.internal(w, err)
		return
	}
	if err := s.store.ChangePassword(r.Context(), u.ID, hash, cookie.Value); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, u.Username, "password.changed", ip)
	w.WriteHeader(http.StatusNoContent)
}

// HashPassword is exported for the first-start admin bootstrap.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
