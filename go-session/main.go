package main

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/rs/cors"

	"github.com/go-redis/redis/v8"
)

var (
	// セキュリティキーは環境変数から読み込む
	key         = []byte(os.Getenv("SESSION_KEY"))
	store       = sessions.NewCookieStore(key)
	redisClient *redis.Client
)

func secret(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Error retrieving session: %v", err)
		return
	}

	// クライアントからのリクエストで送信されたクッキーを取得
	cookie, err := r.Cookie("session-id")
	if err != nil {
		if err == http.ErrNoCookie {
			// クッキーが存在しない場合の処理
			http.Error(w, "No cookie found", http.StatusBadRequest)
			return
		}
		// その他のエラー
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// クッキーの値を取得
	session.ID = cookie.Value

	// セッションの値を確認
	fmt.Println("Session ID from cookie:", session.ID) //

	// Redisからセッションデータを読み込む
	err = loadSessionFromRedis(session)
	if err != nil {
		// エラー処理
		log.Printf("Error loading session: %v", err)
		return
	}

	fmt.Println("Session Values:", session.Values)

	// 認証チェック
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	//fmt.Fprintln(w, "The cake is a lie!")

	// レスポンス
	w.Write([]byte("Secret"))
}

func login(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Error retrieving session: %v", err)
		return
	}

	if session.ID == "" {
		session.ID = strings.TrimRight(
			base32.StdEncoding.EncodeToString(
				securecookie.GenerateRandomKey(32)), "=")
	}

	fmt.Println("Session ID:", session.ID)

	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 1週間
		HttpOnly: true,
		// Secure: true, // HTTPSを使用する場合に有効化
	}

	// 認証成功と見なす
	session.Values["authenticated"] = true
	//test
	//session.Values["foo"] = "bar"

	// Redisにセッションデータを保存
	err = saveSessionToRedis(session)
	if err != nil {
		// エラー処理
		log.Printf("Error saving session: %v", err)
		return
	}

	err = session.Save(r, w)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Error saving session: %v", err)
		return
	}

	// セッションIDをクッキーに設定
	cookie := http.Cookie{
		Name:     "session-id",
		Value:    session.ID,
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true, // JavaScriptからアクセスを防ぐ
		// Secure: true, // HTTPSを使用する場合にコメントアウトを外す
	}

	// クッキーをレスポンスに追加
	http.SetCookie(w, &cookie)

	// セッションの値を確認
	fmt.Println("Session ID:", session.ID)
	fmt.Println("Session Values:", session.Values)

	fmt.Println("Login successful")

	// レスポンス
	w.Write([]byte("Logged in"))
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Error retrieving session: %v", err)
		return
	}

	// セッションオプションの設定
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
		// Secure: true,
	}

	// クライアントからのリクエストで送信されたクッキーを取得
	cookie, err := r.Cookie("session-id")
	if err != nil {
		if err == http.ErrNoCookie {
			// クッキーが存在しない場合の処理
			http.Error(w, "No cookie found", http.StatusBadRequest)
			return
		}
		// その他のエラー
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// クッキーの値を取得
	session.ID = cookie.Value

	// ログアウト処理
	// セッションデータを削除
	delete(session.Values, "authenticated")

	// Redisからセッションを削除
	err = redisClient.Del(context.Background(), session.ID).Err()
	if err != nil {
		log.Printf("Error deleting session from Redis: %v", err)
		// ここでエラーを返すかどうかはアプリケーションの要件によります
	}

	err = session.Save(r, w)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Error saving session: %v", err)
		return
	}

	fmt.Println("Session ID:", session.ID) // ここでは空文字列になる
	fmt.Println("Session Values:", session.Values)
	fmt.Println("Logout successful")

	// レスポンス
	w.Write([]byte("Logged out"))
}

func CreateToken(userID int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	return tokenString, err
}

func VerifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	return token, err
}

func init() {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379", // Redisサーバーのアドレス
		Password: "",               // パスワード（あれば）
		DB:       0,                // 使用するDB
	})

	//store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))
	// Redisをセッションストアとして設定するロジックをここに追加
	//このinit関数は、プログラムが開始されると自動的に実行され、Redisクライアントを初期化します。init 関数は、定義されているパッケージ内で最初に一度だけ実行されるため、特別な呼び出しコードは必要ありません。
}

func convertSessionValuesToMap(values map[interface{}]interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	for key, value := range values {
		strKey, ok := key.(string)
		if !ok {
			return nil, fmt.Errorf("key is not a string: %v", key)
		}
		result[strKey] = value
	}
	return result, nil
}

// Redisにセッションを保存する
func saveSessionToRedis(session *sessions.Session) error {
	// セッションのValuesを変換
	values, err := convertSessionValuesToMap(session.Values)
	if err != nil {
		return err
	}

	// JSONにシリアライズ
	data, err := json.Marshal(values)
	if err != nil {
		return err
	}

	// Redisに保存
	return redisClient.Set(context.Background(), session.ID, data, time.Duration(session.Options.MaxAge)*time.Second).Err()
}

// Redisからセッションを読み込む
func loadSessionFromRedis(session *sessions.Session) error {
	data, err := redisClient.Get(context.Background(), session.ID).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil // セッションが存在しない場合はエラーではない
		}
		return err
	}

	log.Printf("Session is loaded to Redis: %s\n", session.ID)

	// 一時的にmap[string]interface{}型を使用
	tempValues := make(map[string]interface{})
	err = json.Unmarshal(data, &tempValues)
	if err != nil {
		return err
	}

	// session.Valuesをmap[interface{}]interface{}型に変換
	if session.Values == nil {
		session.Values = make(map[interface{}]interface{})
	}
	for k, v := range tempValues {
		session.Values[k] = v
	}

	return nil
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
