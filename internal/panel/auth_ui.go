package panel

import (
	"net/http"
	"strings"
)

func (s *Server) setupPage(w http.ResponseWriter, r *http.Request) {
	if !s.firstRun(r.Context()) {
		redirect(w, r, "/login")
		return
	}
	s.render(w, r, "setup", pageData{Title: "Setup"})
}

func (s *Server) setupSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.firstRun(r.Context()) {
		redirect(w, r, "/login")
		return
	}
	_ = r.ParseForm()
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if username == "" || len(password) < 8 {
		s.render(w, r, "setup", pageData{Title: "Setup", Error: "Username is required and password must be at least 8 characters."})
		return
	}
	if err := s.store.CreateAdmin(r.Context(), username, password); err != nil {
		s.render(w, r, "setup", pageData{Title: "Setup", Error: err.Error()})
		return
	}
	id, _, err := s.store.FindAdmin(r.Context(), username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	token, _, err := s.store.CreateSession(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.setSessionCookie(w, token)
	redirect(w, r, "/")
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if s.firstRun(r.Context()) {
		redirect(w, r, "/setup")
		return
	}
	s.render(w, r, "login", pageData{Title: "Login"})
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if s.firstRun(r.Context()) {
		redirect(w, r, "/setup")
		return
	}
	_ = r.ParseForm()
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	id, hash, err := s.store.FindAdmin(r.Context(), username)
	if err != nil || !VerifyPassword(hash, password) {
		s.render(w, r, "login", pageData{Title: "Login", Error: "Invalid username or password."})
		return
	}
	token, _, err := s.store.CreateSession(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.setSessionCookie(w, token)
	redirect(w, r, "/")
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("ss_panel_session"); err == nil {
		_ = s.store.DeleteSession(r.Context(), c.Value)
	}
	s.clearSessionCookie(w)
	redirect(w, r, "/login")
}
