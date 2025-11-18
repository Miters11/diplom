package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

var privateKey *rsa.PrivateKey
var aesKey []byte
var username string

func initPrivateKey(privateKeyBytes []byte) {
	json.Unmarshal(privateKeyBytes, &privateKey)
}

func saveAESKey() {
	key := sha256.Sum256([]byte("password")) // Фиксированный 32-байтный ключ
	block, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	encrypted := gcm.Seal(nonce, nonce, aesKey, nil)
	os.WriteFile("aes_key.enc", encrypted, 0644)
}
func loadAESKey() {
	if data, err := os.ReadFile("aes_key.enc"); err == nil {
		key := sha256.Sum256([]byte("password"))
		block, _ := aes.NewCipher(key[:])
		gcm, _ := cipher.NewGCM(block)
		nonceSize := gcm.NonceSize()
		nonce, ciphertext := data[:nonceSize], data[nonceSize:]
		aesKey, _ = gcm.Open(nil, nonce, ciphertext, nil)
	}
}

func initAESKey(serverURL, user, pass string) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, _ := client.PostForm(serverURL+"/login", url.Values{"username": {user}, "password": {pass}})
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	encryptedAESStr := result["aes_key_encrypted"].(string)
	encryptedAES, _ := base64.StdEncoding.DecodeString(encryptedAESStr)
	aesKey, _ = rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedAES, nil)
	saveAESKey() // Сохранить локально
}

func encrypt(data []byte) []byte {
	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	return append(nonce, gcm.Seal(nil, nonce, data, nil)...)
}

func decrypt(data []byte) []byte {
	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, _ := gcm.Open(nil, nonce, ciphertext, nil)
	return plaintext
}

func uploadFile(serverURL, filePath string) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	file, _ := os.Open(filePath)
	defer file.Close()
	data, _ := io.ReadAll(file)
	encrypted := encrypt(data)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.WriteField("username", username)
	part, _ := writer.CreateFormFile("file", filePath)
	part.Write(encrypted)
	writer.Close()

	req, _ := http.NewRequest("POST", serverURL+"/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, _ := client.Do(req)
	fmt.Println("Upload response:", resp.Status)
}

func downloadFile(serverURL, filename string) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	req, _ := http.NewRequest("GET", serverURL+"/download/"+filename, nil)
	req.PostForm = url.Values{"username": {username}}
	resp, _ := client.Do(req)
	defer resp.Body.Close()
	encrypted, _ := io.ReadAll(resp.Body)
	decrypted := decrypt(encrypted)
	os.WriteFile(filename, decrypted, 0644)
	fmt.Println("Downloaded and decrypted:", filename)
}

func listFiles(serverURL string) []string {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, _ := client.Get(serverURL + "/listfiles?username=" + username)
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if result["files"] == nil {
		return []string{}
	}
	filesInterface := result["files"].([]interface{})
	var files []string
	for _, f := range filesInterface {
		files = append(files, f.(string))
	}
	return files
}

func main() {
	initPrivateKey([]byte("24340185922162876523766022746035037960661088310402681779167682421697872666450089972020064707537455486819813277653750116281687200809128180132054610584337948628756401455416879855792119453042198363873461699593532411047957417948215734945035408210031062071320584939245325367254732679005029326423190050993288898660391491983139626028133215698459191162038850351587670197485133128342323293338949209786436752428729587240998177063047113687528217313898750476420786227780880073661507388914240401878707786388199103077717365599526531623151493222672361487461855879618913189219899886662324996714793998972621196037757004785691842090559")) // Вставьте
	loadAESKey()                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        // Загрузить сохраненный ключ

	a := app.New()
	w := a.NewWindow("Corporate Cloud Drive")

	userEntry := widget.NewEntry()
	passEntry := widget.NewPasswordEntry()
	loginBtn := widget.NewButton("Login", func() {
		username = userEntry.Text
		password := passEntry.Text
		initAESKey("https://192.168.0.25", username, password)
	})

	uploadBtn := widget.NewButton("Upload", func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err == nil && reader != nil {
				uploadFile("https://192.168.0.25", reader.URI().Path())
			}
		}, w)
	})

	downloadEntry := widget.NewEntry()
	downloadBtn := widget.NewButton("Download", func() {
		downloadFile("https://192.168.0.25", downloadEntry.Text)
	})

	listBtn := widget.NewButton("List Files", func() {
		files := listFiles("https://192.168.0.25")
		listStr := strings.Join(files, "\n")
		dialog.ShowInformation("Your Files", listStr, w)
	})

	w.SetContent(container.NewVBox(
		widget.NewLabel("Username"), userEntry,
		widget.NewLabel("Password"), passEntry, loginBtn,
		uploadBtn,
		widget.NewLabel("Filename to Download"), downloadEntry, downloadBtn,
		listBtn,
	))
	w.ShowAndRun()
}
