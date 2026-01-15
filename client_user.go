//go:build no_glfw
// +build no_glfw

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

var privateKey []byte
var selectedFilename string
var mainWindow fyne.Window

func initPrivateKey(key []byte) {
	privateKey = key
	log.Println("Приватный ключ инициализирован")
}

func encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func saveKeyToFile(id string, key []byte) error {
	keys, err := loadKeysFromFile()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if keys == nil {
		keys = make(map[string]string)
	}

	keys[id] = base64.StdEncoding.EncodeToString(key)

	file, err := os.Create("keys.json")
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewEncoder(file).Encode(keys)
}

func loadKeysFromFile() (map[string]string, error) {
	file, err := os.Open("keys.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var keys map[string]string
	err = json.NewDecoder(file).Decode(&keys)
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func getKeyByID(id string) ([]byte, error) {
	keys, err := loadKeysFromFile()
	if err != nil {
		return nil, err
	}

	keyStr, exists := keys[id]
	if !exists {
		return nil, fmt.Errorf("ключ для ID %s не найден", id)
	}

	return base64.StdEncoding.DecodeString(keyStr)
}

func uploadFile(filePath, username, password string) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		dialog.ShowError(fmt.Errorf("Ошибка генерации ключа: %v", err), mainWindow)
		return
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Ошибка чтения файла: %v", err), mainWindow)
		return
	}

	encryptedData, err := encrypt(data, key)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Ошибка шифрования: %v", err), mainWindow)
		return
	}

	filename := filepath.Base(filePath)
	req, err := http.NewRequest("POST", "https://192.168.0.25/upload?username="+username+"&filename="+filename, bytes.NewReader(encryptedData))
	if err != nil {
		dialog.ShowError(fmt.Errorf("Ошибка создания запроса: %v", err), mainWindow)
		return
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	auth := username + ":" + password
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Ошибка отправки: %v", err), mainWindow)
		return
	}
	defer resp.Body.Close()

	var response struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		dialog.ShowError(fmt.Errorf("Ошибка декодирования ответа: %v", err), mainWindow)
		return
	}

	if err := saveKeyToFile(response.ID, key); err != nil {
		dialog.ShowError(fmt.Errorf("Ошибка сохранения ключа: %v", err), mainWindow)
		return
	}

	dialog.ShowInformation("Успех", "Файл загружен, ID: "+response.ID, mainWindow)
}

func downloadFile(id, username, password string) {
	key, err := getKeyByID(id)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Ошибка получения ключа: %v", err), mainWindow)
		return
	}

	req, err := http.NewRequest("GET", "https://192.168.0.25/download/"+id+"?username="+username, nil)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Ошибка создания запроса: %v", err), mainWindow)
		return
	}
	auth := username + ":" + password
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Ошибка скачивания: %v", err), mainWindow)
		return
	}
	defer resp.Body.Close()

	encryptedData, err := io.ReadAll(resp.Body)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Ошибка чтения данных: %v", err), mainWindow)
		return
	}

	decryptedData, err := decrypt(encryptedData, key)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Ошибка дешифрования: %v", err), mainWindow)
		return
	}

	filename := selectedFilename
	if filename == "" {
		filename = "downloaded_" + id + ".txt"
	}

	saveDialog := dialog.NewFileSave(func(uri fyne.URIWriteCloser, err error) {
		if err != nil {
			dialog.ShowError(err, mainWindow)
			return
		}
		if uri == nil {
			// Пользователь отменил сохранение
			return
		}
		defer uri.Close()
		_, err = uri.Write(decryptedData)
		if err != nil {
			dialog.ShowError(fmt.Errorf("Ошибка сохранения файла: %v", err), mainWindow)
			return
		}
		dialog.ShowInformation("Успех", "Файл сохранен", mainWindow)
	}, mainWindow)
	saveDialog.SetFileName(filename)
	saveDialog.Show()
}

type FileInfo struct {
	ID       string `json:"id"`
	Filename string `json:"filename"`
}

func listFiles(username, password string) ([]FileInfo, error) {
	req, err := http.NewRequest("GET", "https://192.168.0.25/listfiles?username="+username, nil)
	if err != nil {
		return nil, err
	}
	auth := username + ":" + password
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var files []FileInfo
	if err := json.NewDecoder(resp.Body).Decode(&files); err != nil {
		return nil, err
	}
	return files, nil
}

func loginUser(username, password string) error {
	loginData := map[string]string{
		"username": username,
		"password": password,
	}
	jsonData, err := json.Marshal(loginData)
	if err != nil {
		return err
	}

	resp, err := http.Post("https://192.168.0.25/login", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("incorrect credentials")
	}

	var response struct {
		Message    string         `json:"message"`
		PrivateKey rsa.PrivateKey `json:"private_key"`
		Role       string         `json:"role"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}

	initPrivateKey([]byte(fmt.Sprintf("%d", response.PrivateKey.N)))

	return nil
}

func main() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	a := app.NewWithID("cloud-drive-client")
	mainWindow = a.NewWindow("Облачный диск")
	mainWindow.Resize(fyne.NewSize(400, 200))

	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("Логин")
	usernameEntry.OnChanged = func(s string) {
		if len(s) > 25 {
			usernameEntry.SetText(s[:25]) // Обрезает до 25 символов
		}
	}
	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Пароль")
	passwordEntry.OnChanged = func(s string) {
		if len(s) > 25 {
			passwordEntry.SetText(s[:25]) // Обрезает до 25 символов
		}
	}
	filePathEntry := widget.NewEntry()
	filePathEntry.SetPlaceHolder("Путь до файла для отправки")

	idEntry := widget.NewEntry()
	idEntry.SetPlaceHolder("ID файла для загрузки")

	loginButton := widget.NewButton("Авторизация", func() {
		username := usernameEntry.Text
		password := passwordEntry.Text
		if username == "" || password == "" {
			dialog.ShowInformation("Предупреждение", "Введите логин и пароль", mainWindow)
			return
		}

		err := loginUser(username, password)
		if err != nil {
			dialog.ShowError(fmt.Errorf("Ошибка логина: %v", err), mainWindow)
			return
		}

		dialog.ShowInformation("Успех", "Логин успешен", mainWindow)
	})

	selectFileButton := widget.NewButton("Выбор файла", func() {
		username := usernameEntry.Text
		password := passwordEntry.Text
		if username == "" || password == "" {
			dialog.ShowInformation("Предупреждение", "Введите логин и пароль", mainWindow)
			return
		}

		fileWindow := a.NewWindow("Выбор файла")
		fileWindow.Resize(fyne.NewSize(400, 400))

		fileDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(fmt.Errorf("Ошибка выбора файла: %v", err), mainWindow)
				fileWindow.Close()
				return
			}
			if reader == nil {
				fileWindow.Close()
				return
			}
			defer reader.Close()

			filePath := reader.URI().Path()
			filePathEntry.SetText(filePath)
			uploadFile(filePath, username, password)
			fileWindow.Close()
		}, fileWindow)
		fileDialog.Show()
		fileWindow.Show()
	})

	listFilesButton := widget.NewButton("Список файлов", func() {
		username := usernameEntry.Text
		password := passwordEntry.Text
		if username == "" || password == "" {
			dialog.ShowInformation("Предупреждение", "Введите логин и пароль", mainWindow)
			return
		}

		files, err := listFiles(username, password)
		if err != nil {
			dialog.ShowError(fmt.Errorf("Ошибка получения списка файлов: %v", err), mainWindow)
			return
		}

		if len(files) == 0 {
			dialog.ShowInformation("Нет файлов", "У вас нет доступных файлов.", mainWindow)
			return
		}

		var options []string
		fileMap := make(map[string]string)
		filenameMap := make(map[string]string)
		for _, file := range files {
			option := fmt.Sprintf("%s (ID: %s)", file.Filename, file.ID)
			options = append(options, option)
			fileMap[option] = file.ID
			filenameMap[option] = file.Filename
		}

		selectWidget := widget.NewSelect(options, func(selected string) {
			if selected != "" {
				idEntry.SetText(fileMap[selected])
				selectedFilename = filenameMap[selected]
			}
		})
		selectWidget.PlaceHolder = "Выберите файл"
		selectDialog := dialog.NewCustom("Выберите файл для скачивания", "Закрыть", selectWidget, mainWindow)
		selectDialog.Show()
	})

	downloadButton := widget.NewButton("Загрузка файлов", func() {
		username := usernameEntry.Text
		password := passwordEntry.Text
		id := idEntry.Text
		if username == "" || password == "" || id == "" {
			dialog.ShowInformation("Предупреждение", "Введите логин, пароль и ID файла", mainWindow)
			return
		}
		downloadFile(id, username, password)
	})

	mainWindow.SetContent(container.NewVBox(
		widget.NewLabel("Логин:"),
		usernameEntry,
		widget.NewLabel("Пароль:"),
		passwordEntry,
		loginButton,
		widget.NewLabel("Путь до файла для отправки:"),
		filePathEntry,
		selectFileButton,
		listFilesButton,
		widget.NewLabel("ID файла для загрузки:"),
		idEntry,
		downloadButton,
	))

	mainWindow.ShowAndRun()
}
