package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gorilla/csrf"
	"golang.org/x/net/html"
)

// Test Handlers

func TestHandleHome(t *testing.T) {
	postStore := NewInMemoryBlogPostStore()
	req, rr := createRequestResponse("GET", "/", nil)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleHome(w, r, postStore)
	})
	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusOK)
}

func TestHandlePost(t *testing.T) {
	postStore := NewInMemoryBlogPostStore()
	err := postStore.CreatePost(BlogPost{
		Title:    "Test Post",
		Markdown: "# Test Post\nThis is a test post."})

	if err != nil {
		t.Fatalf("Failed to create post: %v", err)
	}

	req, rr := createRequestResponse("GET", "/post/test-post.md", nil)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlePost(w, r, postStore)
	})
	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusOK)
}

func TestHandleLogin(t *testing.T) {
	t.Run("GET /login", testHandleLoginGet)
	t.Run("POST /login with invalid credentials", testHandleLoginPostInvalid)
	t.Run("POST /login with valid credentials", testHandleLoginPostValid)
	t.Run("/login using CSRF", testHandleLoginCsrf)
}

func testHandleLoginGet(t *testing.T) {
	req, rr := createRequestResponse("GET", "/login", nil)
	csrfMiddleware := csrf.Protect(csrfKey)
	handler := csrfMiddleware(http.HandlerFunc(handleLoginGet))
	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusOK)
	checkCsrfFormToken(t, rr)
}

func testHandleLoginPostInvalid(t *testing.T) {
	req, rr := createRequestResponse("POST", "/login", strings.NewReader("username=wronguser&password=wrongpassword"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	handler := http.HandlerFunc(handleLoginPost)

	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusSeeOther)
	checkRedirectLocation(t, rr, "/login")
}

func testHandleLoginPostValid(t *testing.T) {
	req, rr := createRequestResponse("POST", "/login", strings.NewReader("username="+username+"&password="+password))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	handler := http.HandlerFunc(handleLoginPost)

	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusSeeOther)
	checkRedirectLocation(t, rr, "/admin")
	checkCookie(t, rr, "auth", map[string]string{"username": username, "password": password})
}

func testHandleLoginCsrf(t *testing.T) {
	req, rr := createRequestResponse("GET", "/login", nil)
	csrfMiddleware := csrf.Protect(csrfKey)
	handler := csrfMiddleware(http.HandlerFunc(handleLoginGet))
	handler.ServeHTTP(rr, req)

	csrfCookie := extractCsrfCookie(t, rr)
	if csrfCookie == nil {
		t.Fatal("CSRF cookie not found")
	}

	csrfToken, err := extractCsrfTokenFromHTML(rr.Body.String())
	if err != nil {
		t.Fatal("Error extracting CSRF token from HTML:", err)
	}

	// Test without CSRF token
	req, rr = createRequestResponse("POST", "/login", strings.NewReader("username="+username+"&password="+password))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	handler = csrfMiddleware(http.HandlerFunc(handleLoginPost))
	handler.ServeHTTP(rr, req)

	checkStatusCode(t, rr, http.StatusForbidden)

	// Test with CSRF token
	req, rr = createRequestResponse("POST", "/login", strings.NewReader("username="+username+"&password="+password))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrfToken)
	req.AddCookie(csrfCookie)
	handler.ServeHTTP(rr, req)

	checkStatusCode(t, rr, http.StatusSeeOther)
	checkRedirectLocation(t, rr, "/admin")
	checkCookie(t, rr, "auth", map[string]string{"username": username, "password": password})
}

func TestHandleLogout(t *testing.T) {
	req, rr := createRequestResponse("GET", "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "auth", Value: "dummy-auth-value"})

	handler := http.HandlerFunc(handleLogout)

	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusSeeOther)
	checkClearedCookie(t, rr)
}

func TestHandleAdmin(t *testing.T) {
	req, rr := createRequestResponse("GET", "/admin", nil)
	csrfMiddleware := csrf.Protect(csrfKey)
	handler := csrfMiddleware(http.HandlerFunc(handleAdmin))
	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusOK)
	checkCsrfFormToken(t, rr)
}

func TestHandleCreate(t *testing.T) {
	postStore := NewInMemoryBlogPostStore()

	req, rr := createRequestResponse("POST", "/create", nil)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleCreate(w, r, postStore)
	})
	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusBadRequest)

	req, rr = createRequestResponse("POST", "/create", strings.NewReader("title=Test+Post&content=This+is+a+test+post."))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusSeeOther)
	checkPostExists(t, postStore, "test-post.md")
}

func TestHandleEdit(t *testing.T) {
	postStore := NewInMemoryBlogPostStore()
	err := postStore.CreatePost(BlogPost{
		Title:    "Test Post",
		Markdown: "# Test Post\nThis is a test post."})

	if err != nil {
		t.Fatalf("Failed to create post: %v", err)
	}

	t.Run("GET /edit/test-post.md", func(t *testing.T) {
		req, rr := createRequestResponse("GET", "/edit/test-post.md", nil)
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleEditGet(w, r, postStore)
		})
		handler.ServeHTTP(rr, req)
		checkStatusCode(t, rr, http.StatusOK)
	})

	t.Run("POST /edit/test-post.md", func(t *testing.T) {
		form := "title=Updated+Test+Post&content=This+is+an+updated+test+post."
		req, rr := createRequestResponse("POST", "/edit/test-post.md", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleEditPost(w, r, postStore)
		})
		handler.ServeHTTP(rr, req)
		checkStatusCode(t, rr, http.StatusSeeOther)
		checkPostExists(t, postStore, "updated-test-post.md")
	})
}

// Test Utility Functions
func TestBasicAuth(t *testing.T) {
	req, rr := createRequestResponse("GET", "/admin", nil)
	handler := basicAuth(handleAdmin)
	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusUnauthorized)

	value := map[string]string{"username": username, "password": password}

	encoded, err := sCookie.Encode("auth", value)
	if err != nil {
		t.Fatal("Error encoding auth cookie:", err)
	}

	req.AddCookie(&http.Cookie{Name: "auth", Value: encoded})

	rr = httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusOK)
}

func TestIsUserAuthenticated(t *testing.T) {
	req, _ := createRequestResponse("GET", "/", nil)
	if isUserAuthenticated(req) {
		t.Error("User should not be authenticated without a cookie")
	}

	req, _ = createRequestResponse("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "auth", Value: "invalid-cookie-value"})

	if isUserAuthenticated(req) {
		t.Error("User should not be authenticated with an invalid cookie")
	}

	req, _ = createRequestResponse("GET", "/", nil)

	value := map[string]string{"username": username, "password": password}

	encoded, err := sCookie.Encode("auth", value)
	if err != nil {
		t.Fatal("Error encoding auth cookie:", err)
	}

	req.AddCookie(&http.Cookie{Name: "auth", Value: encoded})

	if !isUserAuthenticated(req) {
		t.Error("User should be authenticated with a valid cookie")
	}
}

// Helper Functions

func createRequestResponse(method, url string, body io.Reader) (*http.Request, *httptest.ResponseRecorder) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		panic(err)
	}

	return req, httptest.NewRecorder()
}

func checkStatusCode(t *testing.T, rr *httptest.ResponseRecorder, expected int) {
	if status := rr.Code; status != expected {
		t.Errorf("handler returned wrong status code: got %v want %v", status, expected)
	}
}

func checkRedirectLocation(t *testing.T, rr *httptest.ResponseRecorder, expected string) {
	if location := rr.Header().Get("Location"); location != expected {
		t.Errorf("handler returned wrong redirect location: got %v want %v", location, expected)
	}
}

func checkCookie(t *testing.T, rr *httptest.ResponseRecorder, name string, expectedValue map[string]string) {
	res := rr.Result()
	defer func() {
		err := res.Body.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	var cookieValue string

	for _, cookie := range res.Cookies() {
		if cookie.Name == name {
			cookieValue = cookie.Value
			break
		}
	}

	value := make(map[string]string)
	if err := sCookie.Decode(name, cookieValue, &value); err != nil {
		t.Errorf("Error decoding cookie: %v", err)
	}

	if !reflect.DeepEqual(value, expectedValue) {
		t.Errorf("Expected cookie value '%v', got '%v'", expectedValue, value)
	}
}

func checkClearedCookie(t *testing.T, rr *httptest.ResponseRecorder) {
	res := rr.Result()
	defer func() {
		err := res.Body.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	cookies := res.Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge != -1 || cookies[0].Value != "" {
		t.Error("Cookie was not cleared correctly")
	}
}

// checkCsrfFormToken checks if the CSRF token is present in the form.
func checkCsrfFormToken(t *testing.T, rr *httptest.ResponseRecorder) {
	if !strings.Contains(rr.Body.String(), `name="gorilla.csrf.Token"`) {
		t.Error("CSRF token not found in form")
	}
}

// extractCsrfCookie extracts the CSRF cookie from the Set-Cookie header.
func extractCsrfCookie(t *testing.T, rr *httptest.ResponseRecorder) *http.Cookie {
	res := rr.Result()
	defer func() {
		if err := res.Body.Close(); err != nil {
			// Handle the error if needed
			t.Errorf("Error closing response body: %v", err)
		}
	}()

	for _, cookie := range res.Cookies() {
		if cookie.Name == "_gorilla_csrf" {
			return cookie
		}
	}

	return nil
}

// extractCsrfTokenFromHTML extracts the CSRF token from the HTML response body.
func extractCsrfTokenFromHTML(htmlBody string) (string, error) {
	doc, err := html.Parse(strings.NewReader(htmlBody))
	if err != nil {
		return "", err
	}

	csrfToken, found := findCsrfToken(doc)
	if !found {
		return "", fmt.Errorf("CSRF token not found in HTML")
	}

	return csrfToken, nil
}

// findCsrfToken recursively searches for the CSRF token in the HTML nodes.
func findCsrfToken(n *html.Node) (string, bool) {
	if n.Type == html.ElementNode && n.Data == "input" {
		if name, value := getInputNameAndValue(n); name == "gorilla.csrf.Token" {
			return value, true
		}
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if token, found := findCsrfToken(c); found {
			return token, true
		}
	}

	return "", false
}

// getInputNameAndValue extracts the name and value attributes from an input element.
func getInputNameAndValue(n *html.Node) (string, string) {
	var name, value string

	for _, attr := range n.Attr {
		if attr.Key == "name" {
			name = attr.Val
		}

		if attr.Key == "value" {
			value = attr.Val
		}
	}

	return name, value
}

// checkPostExists checks if a post with the given ID exists in the store.
func checkPostExists(t *testing.T, store *InMemoryBlogPostStore, id string) {
	_, err := store.GetPost(id)
	if err != nil {
		t.Errorf("Post with ID '%s' does not exist", id)
	}
}
