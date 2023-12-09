package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/rs/cors"
)

var (
	key   = []byte("super-secret-key")
	store = sessions.NewCookieStore(key)
)

func secret(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "cookie-name")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// セッションの値を確認
	fmt.Println("Session Values:", session.Values)

	// 認証チェック
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	fmt.Fprintln(w, "The cake is a lie!")
}

func login(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "cookie-name")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 認証成功と見なす
	session.Values["authenticated"] = true
	session.Values["foo"] = "bar"
	session.Values[42] = 43

	err = session.Save(r, w)
	if err != nil {
		fmt.Println("Error saving session:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// セッションの値を確認
	fmt.Println("Session Values:", session.Values)

	fmt.Println("Login successful")
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-name")

	// ログアウト
	session.Values["authenticated"] = false

	session.Save(r, w)

	fmt.Println("Session Values:", session.Values)
	fmt.Println("Logout successful")
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/secret", secret)
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/logout", logout)

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"}, // ReactアプリのURLを設定します
		AllowCredentials: true,                              //これでCookieが使えるようになります
	})

	handler := c.Handler(mux)

	http.ListenAndServe(":8080", handler)
}
