// Package main provides the entry point for the blogging platform.
package main

import (
	"crypto/subtle"
	"embed"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/gomarkdown/markdown"
	"github.com/gorilla/csrf"
	"github.com/gorilla/securecookie"
)

// BlogPost represents a single blog post
type BlogPost struct {
	Title    string
	Content  template.HTML
	Date     time.Time
	Filename string
}

var (
	username     = getEnvOrDefault("JBLOG_USERNAME", "admin")
	password     = getEnvOrDefault("JBLOG_PASSWORD", "changeme")
	isProduction = getEnvOrDefault("GO_ENV", "development") == "production"
	hashKey      = []byte(getEnvOrDefault("HASH_KEY", "very-secret-32-byte-long-key-32-"))
	blockKey     = []byte(getEnvOrDefault("BLOCK_KEY", "a-32-byte-long-key-for-block-32-"))
	sCookie      = securecookie.New(hashKey, blockKey)
	csrfKey      = []byte(getEnvOrDefault("CSRF_KEY", "32-byte-long-auth-key"))
)

//go:embed templates/*
var templatesFS embed.FS

func main() {
	// Initialize Sentry
	err := sentry.Init(sentry.ClientOptions{
		Dsn: os.Getenv("SENTRY_DSN"),
	})
	if err != nil {
		log.Fatalf("sentry.Init: %s", err)
	}

	// Create posts directory if it doesn't exist
	if err := os.MkdirAll("posts", 0755); err != nil {
		sentry.CaptureException(err)
		log.Fatal("Failed to create posts directory:", err)
	} else {
		// Set up HTTP handlers
		router := setupHandlers()

		// Wrap the router with security middleware
		secureRouter := withCsrf(withSecurityHeaders(router))

		log.Println("Starting server on :8100")
		log.Fatal(http.ListenAndServe("[::]:8100", withSentry(secureRouter)))
	}

	defer sentry.Flush(2 * time.Second)
}

// setupHandlers sets up the HTTP handlers
func setupHandlers() *http.ServeMux {
	router := http.NewServeMux()

	router.HandleFunc("GET /", handleHome)
	router.HandleFunc("GET /post/", handlePost)
	router.HandleFunc("GET /login", handleLoginGet)
	router.HandleFunc("POST /login", handleLoginPost)
	router.HandleFunc("GET /logout", handleLogout)
	router.HandleFunc("GET /admin", basicAuth(handleAdmin))
	router.HandleFunc("POST /create", basicAuth(handleCreate))
	router.HandleFunc("GET /edit/", basicAuth(handleEditGet))
	router.HandleFunc("POST /edit/", basicAuth(handleEditPost))

	return router
}

// withSecurityHeaders is a middleware that adds security headers to the response
func withSecurityHeaders(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "+
				"style-src https://cdn.jsdelivr.net https://maxcdn.bootstrapcdn.com 'unsafe-inline'; "+
				"img-src 'self'; font-src https://maxcdn.bootstrapcdn.com; connect-src https://cdn.jsdelivr.net;")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		handler.ServeHTTP(w, r)
	})
}

// withCsrf is a middleware that adds gorilla csrf protection
func withCsrf(handler http.Handler) http.Handler {
	options := []csrf.Option{
		csrf.Secure(isProduction),
	}

	if isProduction {
		options = append(options, csrf.SameSite(csrf.SameSiteStrictMode))
	}

	return csrf.Protect(
		csrfKey,
		options...,
	)(handler)
}

// withSentry is a middleware that recovers from panics and reports them to Sentry
func withSentry(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer sentry.Recover()
		handler.ServeHTTP(w, r)
	})
}

// Handlers

// handleHome handles the home page request
func handleHome(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling home page request")

	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	posts, err := loadBlogPosts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		sentry.CaptureException(err)

		return
	}

	data := struct {
		Posts           []BlogPost
		IsAuthenticated bool
	}{
		Posts:           posts,
		IsAuthenticated: isUserAuthenticated(r),
	}

	renderTemplate(w, "templates/home.html", data)
}

// handlePost handles the individual post page request
func handlePost(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling post page request for:", r.URL.Path)

	filename := strings.TrimPrefix(r.URL.Path, "/post/")
	post, err := loadBlogPost(filename)

	if err != nil {
		http.Error(w, "Post not found", http.StatusNotFound)

		if err != os.ErrNotExist {
			sentry.CaptureException(err)
		}

		return
	}

	data := struct {
		Post            BlogPost
		IsAuthenticated bool
	}{
		Post:            post,
		IsAuthenticated: isUserAuthenticated(r),
	}

	renderTemplate(w, "templates/post.html", data)
}

// handleLoginGet handles the login template rendering
func handleLoginGet(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling login GET request")

	data := struct {
		CSRFField template.HTML
	}{
		CSRFField: csrf.TemplateField(r),
	}
	renderTemplate(w, "templates/login.html", data)
}

// handleLoginPost handles the login processing
func handleLoginPost(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling login POST request")

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	userUsername := r.FormValue("username")
	userPassword := r.FormValue("password")

	if authenticateUser(userUsername, userPassword) {
		setAuthCookie(w)
		http.Redirect(w, r, "/admin", http.StatusSeeOther)

		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// handleLogout handles the logout request
func handleLogout(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling logout request")
	clearAuthCookie(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleAdmin handles the admin page request
func handleAdmin(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling admin page request")

	data := struct {
		CSRFField template.HTML
	}{
		CSRFField: csrf.TemplateField(r),
	}

	renderTemplate(w, "templates/admin.html", data)
}

// handleCreate handles the creation of a new blog post
func handleCreate(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling create post request with method:", r.Method)

	title := r.FormValue("title")
	content := r.FormValue("content")

	if title == "" || content == "" {
		http.Error(w, "Title and content are required", http.StatusBadRequest)
		return
	}

	filename := strings.ToLower(strings.ReplaceAll(title, " ", "-")) + ".md"
	filepath := filepath.Join("posts", filename)

	if err := os.WriteFile(filepath, []byte(content), 0600); err != nil {
		http.Error(w, "Error saving post", http.StatusInternalServerError)
		sentry.CaptureException(err)

		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleEditGet handles the rendering of blog post edit page
func handleEditGet(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling edit GET request")

	filename := strings.TrimPrefix(r.URL.Path, "/edit/")
	content, err := os.ReadFile(filepath.Join("posts", filename))

	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Post not found", http.StatusNotFound)
		} else {
			sentry.CaptureException(err)
			http.Error(w, "Error loading post", http.StatusInternalServerError)
		}

		return
	}

	data := struct {
		Title     string
		Content   string
		Filename  string
		CSRFField template.HTML
	}{
		Title:     strings.TrimSuffix(filename, ".md"),
		Content:   string(content),
		Filename:  filename,
		CSRFField: csrf.TemplateField(r),
	}

	renderTemplate(w, "templates/edit.html", data)
}

// handleEditPost handles the the blog post update
func handleEditPost(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling edit POST request")

	filename := strings.TrimPrefix(r.URL.Path, "/edit/")

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	title := r.FormValue("title")
	content := r.FormValue("content")

	if title == "" || content == "" {
		http.Error(w, "Title and content are required", http.StatusBadRequest)
		return
	}

	newFilename := strings.ToLower(strings.ReplaceAll(title, " ", "-")) + ".md"
	oldFilepath := filepath.Join("posts", filename)
	newFilepath := filepath.Join("posts", newFilename)

	if err := os.WriteFile(newFilepath, []byte(content), 0600); err != nil {
		sentry.CaptureException(err)
		http.Error(w, "Error saving post", http.StatusInternalServerError)

		return
	}

	if oldFilepath != newFilepath {
		if err := os.Remove(oldFilepath); err != nil {
			sentry.CaptureException(err)
			http.Error(w, "Error removing old post", http.StatusInternalServerError)

			return
		}
	}

	http.Redirect(w, r, "/post/"+newFilename, http.StatusSeeOther)
}

// Utility Functions

// loadBlogPosts loads all blog posts from the posts directory
func loadBlogPosts() ([]BlogPost, error) {
	files, err := filepath.Glob("posts/*.md")
	if err != nil {
		return nil, err
	}

	posts := make([]BlogPost, 0, len(files))

	for _, file := range files {
		post, err := loadBlogPost(filepath.Base(file))
		if err != nil {
			return posts, err
		}

		posts = append(posts, post)
	}

	// Sort posts by descending date
	sort.Slice(posts, func(i, j int) bool {
		return posts[i].Date.After(posts[j].Date)
	})

	return posts, nil
}

// loadBlogPost loads a single blog post from a file
func loadBlogPost(filename string) (BlogPost, error) {
	content, err := os.ReadFile(filepath.Join("posts", filename))
	if err != nil {
		return BlogPost{}, err
	}

	htmlContent := markdown.ToHTML(content, nil, nil)
	title := strings.TrimSuffix(filename, ".md")

	info, err := os.Stat(filepath.Join("posts", filename))
	if err != nil {
		return BlogPost{}, err
	}

	return BlogPost{
		Title:    title,
		Content:  template.HTML(htmlContent),
		Date:     info.ModTime(),
		Filename: filename,
	}, nil
}

// basicAuth is a middleware that provides basic authentication
func basicAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isUserAuthenticated(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)

			return
		}

		handler(w, r)
	}
}

// isUserAuthenticated checks if the user is authenticated
func isUserAuthenticated(r *http.Request) bool {
	if cookie, err := r.Cookie("auth"); err == nil {
		value := make(map[string]string)
		if err = sCookie.Decode("auth", cookie.Value, &value); err == nil {
			return subtle.ConstantTimeCompare([]byte(value["username"]), []byte(username)) == 1 &&
				subtle.ConstantTimeCompare([]byte(value["password"]), []byte(password)) == 1
		}
	}

	return false
}

// authenticateUser checks the provided username and password
func authenticateUser(userUsername, userPassword string) bool {
	return subtle.ConstantTimeCompare([]byte(userUsername), []byte(username)) == 1 &&
		subtle.ConstantTimeCompare([]byte(userPassword), []byte(password)) == 1
}

// setAuthCookie sets the authentication cookie
func setAuthCookie(w http.ResponseWriter) {
	value := map[string]string{
		"username": username,
		"password": password,
	}

	encoded, err := sCookie.Encode("auth", value)
	if err != nil {
		log.Println("Error encoding auth cookie:", err)
		return
	}

	cookie := &http.Cookie{
		Name:     "auth",
		Value:    encoded,
		Path:     "/",
		MaxAge:   3600, // 1 hour
		HttpOnly: true,
		Secure:   isProduction,
		SameSite: http.SameSiteLaxMode,
	}
	if isProduction {
		cookie.SameSite = http.SameSiteStrictMode
	}

	http.SetCookie(w, cookie)
}

// clearAuthCookie clears the authentication cookie
func clearAuthCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     "auth",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isProduction,
		SameSite: http.SameSiteLaxMode,
	}
	if isProduction {
		cookie.SameSite = http.SameSiteStrictMode
	}

	http.SetCookie(w, cookie)
}

// renderTemplate renders a template with the provided data
func renderTemplate(w http.ResponseWriter, templateName string, data interface{}) {
	tmpl, err := template.ParseFS(templatesFS, templateName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		sentry.CaptureException(err)

		return
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		sentry.CaptureException(err)
	}
}

// getEnvOrDefault retrieves env variable if set or returns default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return defaultValue
}
