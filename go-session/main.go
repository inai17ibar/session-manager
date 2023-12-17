package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	"github.com/rs/cors"
)

var (
	// セキュリティキーは環境変数から読み込む
	key   = []byte(os.Getenv("SESSION_KEY"))
	store = sessions.NewCookieStore(key)
)

func secret(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "cookie-name")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Error retrieving session: %v", err)
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
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Error retrieving session: %v", err)
		return
	}

	// 認証成功と見なす
	session.Values["authenticated"] = true
	session.Values["foo"] = "bar"
	session.Values[42] = 43

	err = session.Save(r, w)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Error saving session: %v", err)
		return
	}

	// セッションの値を確認
	fmt.Println("Session Values:", session.Values)

	fmt.Println("Login successful")
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "cookie-name")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Error retrieving session: %v", err)
		return
	}

	// ログアウト
	session.Values["authenticated"] = false
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Error saving session: %v", err)
		return
	}

	fmt.Println("Session Values:", session.Values)
	fmt.Println("Logout successful")
}

func main() {
	// 環境変数 SESSION_KEY が設定されていない場合は、アプリケーションを終了
	if os.Getenv("SESSION_KEY") == "" {
		log.Fatal("SESSION_KEY environment variable is not set")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/secret", secret)
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/logout", logout)

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"}, // ReactアプリのURLを設定
		AllowCredentials: true,                              // Cookieが使えるように設定
	})

	handler := c.Handler(mux)

	log.Fatal(http.ListenAndServe(":8080", handler))
}
