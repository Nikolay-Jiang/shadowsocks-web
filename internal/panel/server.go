package panel

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/Nikolay-Jiang/shadowsocks-web/internal/protocol"
)

//go:embed templates/*.html
var templateFS embed.FS

type Config struct {
	Listen       string
	DataDir      string
	DBPath       string
	PublicURL    string
	CookieSecure bool
}

func DefaultConfig() Config {
	return Config{
		Listen:  "127.0.0.1:8080",
		DataDir: "data",
	}
}

type Server struct {
	cfg    Config
	store  *Store
	crypt  *Crypt
	mux    *http.ServeMux
	pages  map[string]*template.Template
	secure bool
}

func New(cfg Config) (*Server, error) {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8080"
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "data"
	}
	if cfg.DBPath == "" {
		cfg.DBPath = filepath.Join(cfg.DataDir, "panel.db")
	}
	crypt, err := OpenCrypt(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	store, err := OpenStore(cfg.DBPath, crypt)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, store: store, crypt: crypt, mux: http.NewServeMux(), secure: cfg.CookieSecure}
	if err := s.loadTemplates(); err != nil {
		_ = store.Close()
		return nil, err
	}
	s.routes()
	return s, nil
}

func (s *Server) Close() error { return s.store.Close() }

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) loadTemplates() error {
	names, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return err
	}
	s.pages = make(map[string]*template.Template)
	for _, name := range names {
		base := filepath.Base(name)
		if base == "layout.html" {
			continue
		}
		t, err := template.New("layout").Funcs(template.FuncMap{
			"bytes":       formatBytes,
			"date":        formatDate,
			"dateInput":   dateInput,
			"statusClass": statusClass,
			"short":       shortID,
		}).ParseFS(templateFS, "templates/layout.html", name)
		if err != nil {
			return fmt.Errorf("parse %s: %w", base, err)
		}
		s.pages[strings.TrimSuffix(base, ".html")] = t
	}
	return nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	s.mux.HandleFunc("GET /setup", s.setupPage)
	s.mux.HandleFunc("POST /setup", s.setupSubmit)
	s.mux.HandleFunc("GET /login", s.loginPage)
	s.mux.HandleFunc("POST /login", s.loginSubmit)
	s.mux.HandleFunc("POST /logout", s.auth(s.logout))

	s.mux.HandleFunc("GET /", s.auth(s.dashboard))
	s.mux.HandleFunc("GET /nodes", s.auth(s.nodesPage))
	s.mux.HandleFunc("POST /nodes", s.auth(s.nodeCreate))
	s.mux.HandleFunc("GET /nodes/{id}", s.auth(s.nodePage))
	s.mux.HandleFunc("POST /nodes/{id}", s.auth(s.nodeUpdate))
	s.mux.HandleFunc("POST /nodes/{id}/delete", s.auth(s.nodeDelete))
	s.mux.HandleFunc("POST /nodes/{id}/token", s.auth(s.nodeRotateToken))
	s.mux.HandleFunc("GET /users", s.auth(s.usersPage))
	s.mux.HandleFunc("POST /users", s.auth(s.userCreate))
	s.mux.HandleFunc("GET /users/{id}", s.auth(s.userPage))
	s.mux.HandleFunc("POST /users/{id}", s.auth(s.userUpdate))
	s.mux.HandleFunc("POST /users/{id}/delete", s.auth(s.userDelete))
	s.mux.HandleFunc("POST /users/{id}/assign", s.auth(s.userAssign))
	s.mux.HandleFunc("POST /users/{id}/unassign", s.auth(s.userUnassign))
	s.mux.HandleFunc("GET /audit", s.auth(s.auditPage))

	s.mux.HandleFunc("POST /api/v1/agent/enroll", s.agentEnroll)
	s.mux.HandleFunc("GET /api/v1/agent/sync", s.agentSync)
	s.mux.HandleFunc("POST /api/v1/agent/report", s.agentReport)
}

type pageData struct {
	Title    string
	Admin    string
	CSRF     string
	Flash    string
	Error    string
	Data     any
	Version  string
	PanelURL string
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data pageData) {
	if data.Title == "" {
		data.Title = "shadowsocks-web"
	}
	tpl := s.pages[page]
	if tpl == nil {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) firstRun(ctx context.Context) bool {
	n, err := s.store.AdminCount(ctx)
	return err == nil && n == 0
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.session(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if err := r.ParseForm(); err != nil || r.FormValue("csrf") != sess.CSRF {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		ctx := context.WithValue(r.Context(), sessionKey{}, sess)
		next(w, r.WithContext(ctx))
	}
}

type sessionKey struct{}

func sessionFrom(r *http.Request) Session {
	s, _ := r.Context().Value(sessionKey{}).(Session)
	return s
}

func (s *Server) session(r *http.Request) (Session, error) {
	cookie, err := r.Cookie("ss_panel_session")
	if err != nil {
		return Session{}, err
	}
	return s.store.GetSession(r.Context(), cookie.Value)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "ss_panel_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL / time.Second),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "ss_panel_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *Server) audit(r *http.Request, sess Session, action, targetType, targetID, detail string) {
	_ = s.store.AddAudit(r.Context(), sess.Username, action, targetType, targetID, detail, clientIP(r))
}

func (s *Server) pageFor(w http.ResponseWriter, r *http.Request, name string, data pageData) {
	sess, _ := s.session(r)
	data.Admin = sess.Username
	data.CSRF = sess.CSRF
	data.Version = protocol.Version
	data.PanelURL = s.publicURL(r)
	s.render(w, r, name, data)
}

// publicURL is what agents should put in panel_url. Configure it explicitly
// with -public-url or SS_PANEL_PUBLIC_URL; otherwise derive it from the
// request, including the usual reverse-proxy scheme header.
func (s *Server) publicURL(r *http.Request) string {
	if configured := strings.TrimRight(strings.TrimSpace(s.cfg.PublicURL), "/"); configured != "" {
		return configured
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))); forwarded == "http" || forwarded == "https" {
		scheme = forwarded
	}
	return scheme + "://" + r.Host
}

func redirect(w http.ResponseWriter, r *http.Request, path string) {
	http.Redirect(w, r, path, http.StatusSeeOther)
}

func formBool(r *http.Request, name string) bool {
	return r.FormValue(name) == "on" || r.FormValue(name) == "1" || r.FormValue(name) == "true"
}

func parseID(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "/\\") {
		return "", errors.New("invalid id")
	}
	return raw, nil
}
