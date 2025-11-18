package main

import (
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type User struct {
	ID         int
	Username   string
	Password   string
	Role       string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

var db *sql.DB

func init() {
	var err error
	db, err = sql.Open("sqlite", "./cloud.db")
	if err != nil {
		fmt.Println("Error opening DB:", err)
		panic(err)
	}
	fmt.Println("DB opened successfully")

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT,
        private_key BLOB,
        public_key BLOB
    )`)
	if err != nil {
		fmt.Println("Error creating users table:", err)
		panic(err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        owner TEXT,
        data BLOB
    )`)
	if err != nil {
		fmt.Println("Error creating files table:", err)
		panic(err)
	}
	fmt.Println("Tables created successfully")
}

func hashPassword(password string) string {
	hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hashed)
}

func checkPassword(hashed, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password)) == nil
}

func register(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	role := c.PostForm("role")

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	privateKeyBytes, _ := json.Marshal(privateKey)
	publicKeyBytes, _ := json.Marshal(publicKey)

	hashedPassword := hashPassword(password)
	_, err := db.Exec("INSERT INTO users (username, password, role, private_key, public_key) VALUES (?, ?, ?, ?, ?)",
		username, hashedPassword, role, privateKeyBytes, publicKeyBytes)
	if err != nil {
		c.JSON(400, gin.H{"error": "User exists"})
		return
	}

	c.JSON(200, gin.H{"message": "Registered", "private_key": privateKeyBytes})
}

func login(c *gin.Context) {
	var loginData struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&loginData); err != nil {
		c.JSON(400, gin.H{"error": "Invalid JSON"})
		return
	}

	var hashedPassword string
	var privateKeyBytes []byte
	var role string
	err := db.QueryRow("SELECT password, private_key, role FROM users WHERE username = ?", loginData.Username).Scan(&hashedPassword, &privateKeyBytes, &role)
	if err != nil || !checkPassword(hashedPassword, loginData.Password) {
		c.JSON(401, gin.H{"error": "Invalid credentials"})
		return
	}

	var privateKey rsa.PrivateKey
	json.Unmarshal(privateKeyBytes, &privateKey)
	c.JSON(200, gin.H{"message": "Logged in", "private_key": privateKey, "role": role})
}

func upload(c *gin.Context) {
	username := c.Query("username")
	encodedFilename := c.Query("filename")
	if username == "" {
		c.JSON(400, gin.H{"error": "Username required"})
		return
	}

	filename, err := url.QueryUnescape(encodedFilename)
	if err != nil {
		fmt.Println("Error unescaping filename:", err)
		filename = "uploaded_file"
	}
	if filename == "" {
		filename = "uploaded_file"
	}
	fmt.Println("Filename after unescape:", filename)

	authHeader := c.GetHeader("Authorization")
	if !checkBasicAuth(authHeader, username) {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	data, err := c.GetRawData()
	if err != nil {
		c.JSON(400, gin.H{"error": "No data"})
		return
	}

	var id int
	err = db.QueryRow("INSERT INTO files (name, owner, data) VALUES (?, ?, ?) RETURNING id", filename, username, data).Scan(&id)
	if err != nil {
		c.JSON(500, gin.H{"error": "Upload failed"})
		return
	}

	c.JSON(200, gin.H{"id": fmt.Sprintf("%d", id)})
}

func download(c *gin.Context) {
	id := c.Param("id")
	username := c.Query("username")
	if username == "" {
		c.JSON(400, gin.H{"error": "Username required"})
		return
	}

	authHeader := c.GetHeader("Authorization")
	if !checkBasicAuth(authHeader, username) {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	var data []byte
	var owner string
	err := db.QueryRow("SELECT data, owner FROM files WHERE id = ?", id).Scan(&data, &owner)
	if err != nil || owner != username {
		c.JSON(404, gin.H{"error": "File not found"})
		return
	}

	c.Data(200, "application/octet-stream", data)
}

func listfiles(c *gin.Context) {
	username := c.Query("username")
	if username == "" {
		c.JSON(400, gin.H{"error": "Username required"})
		return
	}

	authHeader := c.GetHeader("Authorization")
	if !checkBasicAuth(authHeader, username) {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	rows, err := db.Query("SELECT id, name FROM files WHERE owner = ?", username)
	if err != nil {
		c.JSON(500, gin.H{"error": "DB error"})
		return
	}
	defer rows.Close()

	var files []gin.H
	for rows.Next() {
		var id int
		var name string
		rows.Scan(&id, &name)
		files = append(files, gin.H{"id": fmt.Sprintf("%d", id), "filename": name})
	}

	c.JSON(200, files)
}

func createUser(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if !checkAdminAuth(authHeader) {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}
	username := c.PostForm("username")
	password := c.PostForm("password")
	role := c.PostForm("role")
	fmt.Println("Received: username =", username, "password =", password, "role =", role) // Лог полученных данных
	if username == "" || password == "" || role == "" {
		fmt.Println("Empty fields")
		c.JSON(400, gin.H{"error": "Empty fields"})
		return
	}
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey
	privateKeyBytes, _ := json.Marshal(privateKey)
	publicKeyBytes, _ := json.Marshal(publicKey)
	hashedPassword := hashPassword(password)
	_, err := db.Exec("INSERT INTO users (username, password, role, private_key, public_key) VALUES (?, ?, ?, ?, ?)",
		username, hashedPassword, role, privateKeyBytes, publicKeyBytes)
	if err != nil {
		fmt.Println("DB error:", err) // Лог ошибки БД
		c.JSON(400, gin.H{"error": "User exists or DB error"})
		return
	}
	fmt.Println("User created:", username, role)
	c.JSON(200, gin.H{"message": "User created"})
}

func listUsers(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if !checkAdminAuth(authHeader) {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	rows, err := db.Query("SELECT username, role FROM users")
	if err != nil {
		c.JSON(500, gin.H{"error": "DB error"})
		return
	}
	defer rows.Close()

	var users []gin.H
	for rows.Next() {
		var username, role string
		rows.Scan(&username, &role)
		users = append(users, gin.H{"username": username, "role": role})
	}

	c.JSON(200, users)
}

func updateUser(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if !checkAdminAuth(authHeader) {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	username := c.PostForm("username")
	newPassword := c.PostForm("password")

	hashedPassword := hashPassword(newPassword)
	_, err := db.Exec("UPDATE users SET password = ? WHERE username = ?", hashedPassword, username)
	if err != nil {
		c.JSON(500, gin.H{"error": "Update failed"})
		return
	}

	c.JSON(200, gin.H{"message": "Password updated"})
}

func deleteUser(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if !checkAdminAuth(authHeader) {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	username := c.PostForm("username")
	_, err := db.Exec("DELETE FROM users WHERE username = ?", username)
	if err != nil {
		c.JSON(500, gin.H{"error": "Delete failed"})
		return
	}

	c.JSON(200, gin.H{"message": "User deleted"})
}

func backupDB(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if !checkAdminAuth(authHeader) {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	backupPath := fmt.Sprintf("./backups/cloud_%s.db", timestamp)
	os.MkdirAll("./backups", 0755)

	src, err := os.Open("./cloud.db")
	if err != nil {
		c.JSON(500, gin.H{"error": "Backup failed"})
		return
	}
	defer src.Close()

	dst, err := os.Create(backupPath)
	if err != nil {
		c.JSON(500, gin.H{"error": "Backup failed"})
		return
	}
	defer dst.Close()

	io.Copy(dst, src)
	c.JSON(200, gin.H{"message": "Backup created", "path": backupPath})
}

func switchDB(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if !checkAdminAuth(authHeader) {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	backupPath := c.PostForm("path")
	if backupPath == "" {
		c.JSON(400, gin.H{"error": "Path required"})
		return
	}

	src, err := os.Open(backupPath)
	if err != nil {
		c.JSON(500, gin.H{"error": "Switch failed"})
		return
	}
	defer src.Close()

	dst, err := os.Create("./cloud.db")
	if err != nil {
		c.JSON(500, gin.H{"error": "Switch failed"})
		return
	}
	defer dst.Close()

	io.Copy(dst, src)
	c.JSON(200, gin.H{"message": "DB switched"})
}

func checkBasicAuth(authHeader, expectedUsername string) bool {
	if authHeader == "" || !strings.HasPrefix(authHeader, "Basic ") {
		return false
	}
	encoded := strings.TrimPrefix(authHeader, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return false
	}
	username := parts[0]
	var hashedPassword string
	err = db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&hashedPassword)
	if err != nil {
		return false
	}
	return username == expectedUsername && checkPassword(hashedPassword, parts[1])
}

func checkAdminAuth(authHeader string) bool {
	if authHeader == "" || !strings.HasPrefix(authHeader, "Basic ") {
		return false
	}
	encoded := strings.TrimPrefix(authHeader, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return false
	}
	username := parts[0]
	var hashedPassword, role string
	err = db.QueryRow("SELECT password, role FROM users WHERE username = ?", username).Scan(&hashedPassword, &role)
	if err != nil {
		return false
	}
	return role == "admin" && checkPassword(hashedPassword, parts[1])
}

func main() {
	r := gin.Default()
	r.POST("/register", register)
	r.POST("/login", login)
	r.POST("/upload", upload)
	r.GET("/download/:id", download)
	r.GET("/listfiles", listfiles)
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Cloud Drive API is running"})
	})
	r.POST("/create_user", createUser)
	r.GET("/list_users", listUsers)
	r.POST("/update_user", updateUser)
	r.POST("/delete_user", deleteUser)
	r.POST("/backup_db", backupDB)
	r.POST("/switch_db", switchDB)
	r.RunTLS(":443", "cert.pem", "key.pem")
}
