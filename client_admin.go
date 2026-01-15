//go:build no_glfw
// +build no_glfw

package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

var privateKey []byte
var userRole string

func initPrivateKey(key []byte) {
	privateKey = key
	log.Println("Приватный ключ инициализирован")
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
		return fmt.Errorf("неверные credentials")
	}

	var response struct {
		Message    string         `json:"message"`
		PrivateKey rsa.PrivateKey `json:"private_key"`
		Role       string         `json:"role"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}

	userRole = response.Role
	initPrivateKey([]byte(fmt.Sprintf("%d", response.PrivateKey.N)))

	return nil
}

func createUser(username, password, role, adminUsername, adminPassword string) error {
	data := url.Values{}
	data.Set("username", username)
	data.Set("password", password)
	data.Set("role", role)
	req, err := http.NewRequest("POST", "https://192.168.0.25/create_user", strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	auth := adminUsername + ":" + adminPassword
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	fmt.Println("Create user status code:", resp.StatusCode)
	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to create user, status: %d", resp.StatusCode)
	}
	return nil
}

func listUsers(adminUsername, adminPassword string) ([]map[string]string, error) {
	req, err := http.NewRequest("GET", "https://192.168.0.25/list_users", nil)
	if err != nil {
		return nil, err
	}
	auth := adminUsername + ":" + adminPassword
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var users []map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, err
	}
	return users, nil
}

func updateUser(username, newPassword, adminUsername, adminPassword string) error {
	data := url.Values{}
	data.Set("username", username)
	data.Set("password", newPassword)
	req, err := http.NewRequest("POST", "https://192.168.0.25/update_user", strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	auth := adminUsername + ":" + adminPassword
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to update user, status: %d", resp.StatusCode)
	}
	return nil
}

func deleteUser(username, adminUsername, adminPassword string) error {
	req, err := http.NewRequest("POST", "https://192.168.0.25/delete_user", nil)
	if err != nil {
		return err
	}
	req.PostForm = map[string][]string{
		"username": {username},
	}
	auth := adminUsername + ":" + adminPassword
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to delete user")
	}

	return nil
}

func backupDB(adminUsername, adminPassword string) error {
	req, err := http.NewRequest("POST", "https://192.168.0.25/backup_db", nil)
	if err != nil {
		return err
	}
	auth := adminUsername + ":" + adminPassword
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to backup DB")
	}

	return nil
}

func switchDB(path, adminUsername, adminPassword string) error {
	req, err := http.NewRequest("POST", "https://192.168.0.25/switch_db", nil)
	if err != nil {
		return err
	}
	req.PostForm = map[string][]string{
		"path": {path},
	}
	auth := adminUsername + ":" + adminPassword
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to switch DB")
	}

	return nil
}

func limitInput(entry *widget.Entry) {
	entry.OnChanged = func(s string) {
		if len(s) > 25 {
			entry.SetText(s[:25])
		}
	}
}

var mainWindow fyne.Window

func main() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	a := app.NewWithID("cloud-drive-client")
	mainWindow = a.NewWindow("Облачный диск")
	mainWindow.Resize(fyne.NewSize(400, 200))
	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("Логин")
	limitInput(usernameEntry)
	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Пароль")
	limitInput(passwordEntry)
	adminButtons := container.NewVBox()

	loginButton := widget.NewButton("Авторизация", func() {
		username := usernameEntry.Text
		password := passwordEntry.Text
		if username == "" || password == "" {
			dialog.ShowInformation("Предупреждение", "Введите логин и пароль", mainWindow)
			return
		}
		err := loginUser(username, password)
		if err != nil {
			dialog.ShowError(fmt.Errorf("Ошибка авторизации: %v", err), mainWindow)
			return
		}

		log.Println("Авторизация успешена, роль:", userRole)

		if userRole == "admin" {
			adminButtons.RemoveAll()
			adminButtons.Add(widget.NewButton("Управление пользователями", func() {
				adminWindow := a.NewWindow("Управление пользователями")
				adminWindow.Resize(fyne.NewSize(500, 600))
				userLabel := widget.NewLabel("")
				userLabel.Wrapping = fyne.TextWrapWord
				userLabel.Alignment = fyne.TextAlignLeading // ✅ РАБОТАЕТ! Только для Label!
				userLabel.TextStyle.Bold = false

				// Оборачиваем в скролл для поддержки прокрутки
				userContainer := container.NewScroll(userLabel)
				userContainer.SetMinSize(fyne.NewSize(780, 100))

				var refreshList func()
				refreshList = func() {
					users, err := listUsers(username, password)
					if err != nil {
						dialog.ShowError(fmt.Errorf("Ошибка получения списка пользователей: %v", err), mainWindow)
						return
					}

					// Формируем текст: каждая строка — один пользователь
					var lines []string
					for _, u := range users {
						lines = append(lines, fmt.Sprintf("%s (%s)", u["username"], u["role"]))
					}

					// Объединяем в один текст с переносами
					userLabel.SetText(strings.Join(lines, "\n"))
				}

				refreshList()
				newUsernameEntry := widget.NewEntry()
				newUsernameEntry.SetPlaceHolder("Новый логин")
				limitInput(newUsernameEntry)
				newPasswordEntry := widget.NewPasswordEntry()
				newPasswordEntry.SetPlaceHolder("Новый пароль")
				limitInput(newPasswordEntry)
				roleSelect := widget.NewSelect([]string{"user", "admin"}, func(selected string) {})
				roleSelect.SetSelected("user") // Default role

				createButton := widget.NewButton("Создать пользователя", func() {
					newUsername := newUsernameEntry.Text
					newPassword := newPasswordEntry.Text
					role := roleSelect.Selected
					fmt.Println("Client sending: username =", newUsername, "password =", newPassword, "role =", role)
					if newUsername == "" || newPassword == "" || role == "" {
						dialog.ShowInformation("Предупреждение", "Заполните все поля", mainWindow)
						return
					}
					err := createUser(newUsername, newPassword, role, username, password)
					if err != nil {
						dialog.ShowError(fmt.Errorf("Ошибка создания пользователя: %v", err), mainWindow)
					} else {
						dialog.ShowInformation("Успех", "Пользователь создан", mainWindow)
						refreshList()
					}
				})

				updateUsernameEntry := widget.NewEntry()
				updateUsernameEntry.SetPlaceHolder("Пользователь для смены")
				limitInput(updateUsernameEntry)
				updatePasswordEntry := widget.NewPasswordEntry()
				updatePasswordEntry.SetPlaceHolder("Новый пароль")
				limitInput(updatePasswordEntry)
				updateButton := widget.NewButton("Обновить пароль", func() {
					updateUsername := updateUsernameEntry.Text
					newPassword := updatePasswordEntry.Text
					if updateUsername == "" || newPassword == "" {
						dialog.ShowInformation("Предупреждение", "Заполните все поля", mainWindow)
						return
					}
					err := updateUser(updateUsername, newPassword, username, password)
					if err != nil {
						dialog.ShowError(fmt.Errorf("Ошибка обновления пользователя: %v", err), mainWindow)
					} else {
						dialog.ShowInformation("Успех", "Пароль обновлен", mainWindow)
					}
				})

				deleteUsernameEntry := widget.NewEntry()
				deleteUsernameEntry.SetPlaceHolder("Пользователь для удаления")
				limitInput(deleteUsernameEntry)
				deleteButton := widget.NewButton("Удаление пользователя", func() {
					deleteUsername := deleteUsernameEntry.Text
					if deleteUsername == "" {
						dialog.ShowInformation("Предупреждение", "Введите логин", mainWindow)
						return
					}
					err := deleteUser(deleteUsername, username, password)
					if err != nil {
						dialog.ShowError(fmt.Errorf("Ошибка удаления пользователя: %v", err), mainWindow)
					} else {
						dialog.ShowInformation("Успех", "Пользователь удален", mainWindow)
						refreshList()
					}
				})

				adminWindow.SetContent(container.NewVBox(
					widget.NewLabel("Создать пользователя:"),
					newUsernameEntry,
					newPasswordEntry,
					roleSelect,
					createButton,
					widget.NewLabel("Обновить пароль:"),
					updateUsernameEntry,
					updatePasswordEntry,
					updateButton,
					widget.NewLabel("Удалить пользователя:"),
					deleteUsernameEntry,
					widget.NewLabel("Список пользователей:"),
					userContainer,
					deleteButton,
				))
				adminWindow.Show()
			}))

			adminButtons.Add(widget.NewButton("Backup DB", func() {
				err := backupDB(username, password)
				if err != nil {
					dialog.ShowError(fmt.Errorf("Ошибка backup: %v", err), mainWindow)
				} else {
					dialog.ShowInformation("Успех", "Backup создан", mainWindow)
				}
			}))

			adminButtons.Add(widget.NewButton("Switch DB", func() {
				pathEntry := widget.NewEntry()
				pathEntry.SetPlaceHolder("Backup Path")
				switchDialog := dialog.NewCustom("Switch DB", "Switch", container.NewVBox(pathEntry), mainWindow)
				switchDialog.SetOnClosed(func() {
					path := pathEntry.Text
					if path != "" {
						err := switchDB(path, username, password)
						if err != nil {
							dialog.ShowError(fmt.Errorf("Ошибка switch: %v", err), mainWindow)
						} else {
							dialog.ShowInformation("Успех", "DB switched", mainWindow)
						}
					}
				})
				switchDialog.Show()
			}))
		}
	})

	mainWindow.SetContent(container.NewVBox(
		widget.NewLabel("Логин:"),
		usernameEntry,
		widget.NewLabel("Пароль:"),
		passwordEntry,
		loginButton,
		adminButtons,
	))
	mainWindow.ShowAndRun()
}
