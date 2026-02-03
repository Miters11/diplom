//go:build no_glfw
// +build no_glfw

package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

const (
	serverip = "192.168.0.15"
)

// данные для кузнечика
const (
	BlockSize = 16 // 128 бит
	KeySize   = 32 // 256 бит
	Rounds    = 10 // Количество раундов
)

type Kuznechik struct {
	keys [Rounds + 1][BlockSize]byte // список раундовых ключей (11 ключей: 10 раундов + финальный)
}

// генератор раундовых ключей
func NewKuznechik(key []byte) (*Kuznechik, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("недопустимый размер ключа: ожидается %d байт, получено %d", KeySize, len(key))
	}
	k := &Kuznechik{}
	k.expandKey(key) // генерируем раундовые ключи
	return k, nil
}

// генерируем 1 hключей раундов (0..10) на основе исходного 256-битного ключа
func (k *Kuznechik) expandKey(key []byte) {
	// первые два ключа раунда — это первые 16 и следующие 16 байт исходного ключа
	copy(k.keys[0][:], key[:16])
	copy(k.keys[1][:], key[16:])

	constants := make([]byte, 160) // 10 раундов * 16 байт = 160 байт

	for i := 2; i <= Rounds; i++ {
		k.keys[i] = k.keys[i-2]
		k.linearTransform(k.keys[i][:])
		k.addConstant(k.keys[i][:], constants[(i-2)*16:(i-1)*16])

		k.substitute(k.keys[i][:])

		// Ещё раз линейное преобразование
		k.linearTransform(k.keys[i][:])

		// XOR с ключом предыдущего раунда
		k.xorWithKey(k.keys[i][:], k.keys[i-1])
	}
}

// шифрование блоков данных (16 байт) с использованием раундовых ключей
func (k *Kuznechik) Encrypt(dst, src []byte) {
	block := make([]byte, BlockSize)
	copy(block, src)

	// 10 раундов: XOR → S-блок → R-функция
	for i := 0; i < Rounds; i++ {
		k.xorWithKey(block, k.keys[i]) // XOR с ключом раунда
		k.substitute(block)            // S-блок (нелинейная замена)
		k.linearTransform(block)       // линейное преобразование
	}

	// финальный XOR с последним ключом (ключ 10)
	k.xorWithKey(block, k.keys[Rounds])
	copy(dst, block) // запись зашифрованного файла
}

// расшифровываем один блок данных (16 байт) — обратный процесс шифрования
func (k *Kuznechik) Decrypt(dst, src []byte) {
	block := make([]byte, BlockSize)
	copy(block, src) // копируем зашифрованный блок

	// проходим раунды в обратном порядке: от 10 до 1
	for i := Rounds; i > 0; i-- {
		k.xorWithKey(block, k.keys[i])  // XOR с ключом раунда
		k.inverseLinearTransform(block) // Обратное линейное преобразование
		k.inverseSubstitute(block)      // Обратный S-блок
	}

	// финальный XOR с ключом 0
	k.xorWithKey(block, k.keys[0])
	copy(dst, block) // записываем расшифрованный блок
}

// S-блок к каждому байту блока при замене
func (k *Kuznechik) substitute(block []byte) {
	sbox := [256]byte{
		0xfc, 0xee, 0xdd, 0x11, 0xcf, 0x6e, 0x31, 0x16, 0xfb, 0xc4, 0xfa, 0xda, 0x23, 0xc5, 0x04, 0x4d,
		0xe9, 0x77, 0xf0, 0xdb, 0x93, 0x2e, 0x99, 0xba, 0x17, 0x36, 0xf1, 0xbb, 0x14, 0xcd, 0x5f, 0xc1,
		0xf9, 0x18, 0x65, 0x5a, 0xe2, 0x5c, 0xef, 0x21, 0x81, 0x1c, 0x3c, 0x42, 0x8b, 0x01, 0x8e, 0x4f,
		0x05, 0x84, 0x02, 0xae, 0xe3, 0x6a, 0x8a, 0x66, 0x21, 0x3f, 0x6e, 0x49, 0xb0, 0x97, 0x9a, 0x85,
		0xd3, 0x84, 0x1d, 0x8b, 0x56, 0xc6, 0xe8, 0xf3, 0x75, 0x1a, 0x89, 0x6b, 0x37, 0x8e, 0xdb, 0x49,
		0x4e, 0x58, 0x67, 0x0c, 0xe1, 0x47, 0x3a, 0x1d, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
		0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
		0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
		0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
		0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
		0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
		0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
		0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
		0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
		0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
	}
	for i := range block {
		block[i] = sbox[block[i]] // заменяем байт по S-блоку
	}
}

// обратный S-блок для расшифрования
func (k *Kuznechik) inverseSubstitute(block []byte) {
	invSbox := [256]byte{
		0xa5, 0x2d, 0x32, 0x8f, 0x0e, 0x30, 0x38, 0xc0, 0x54, 0xe6, 0x9e, 0x39, 0x55, 0x7e, 0x52, 0x91,
		0x64, 0x03, 0x57, 0x5a, 0x1c, 0x60, 0x07, 0x18, 0x21, 0x72, 0xa8, 0xd1, 0x29, 0xc6, 0xa4, 0x3f,
		0xe0, 0x27, 0x8d, 0x0c, 0x82, 0xea, 0xae, 0xb4, 0x9a, 0x63, 0x49, 0xe5, 0x42, 0xe4, 0x15, 0xb7,
		0xc8, 0x06, 0x70, 0x9d, 0x41, 0x75, 0x19, 0xc9, 0xaa, 0xfc, 0x4d, 0xbf, 0x2a, 0x73, 0x84, 0xd5,
		0xc3, 0xaf, 0x2b, 0x86, 0xa7, 0xb1, 0xb2, 0x5b, 0x46, 0xd3, 0x9f, 0xfd, 0xd4, 0x0f, 0x9c, 0x2f,
		0x9b, 0x43, 0xef, 0xd9, 0x79, 0xb6, 0x53, 0x7f, 0xc1, 0xf0, 0x23, 0xe7, 0x25, 0x5e, 0xb5, 0x1e,
		0xa2, 0xdf, 0xa6, 0xfe, 0xac, 0x22, 0xf9, 0xe2, 0x4a, 0xbc, 0x35, 0xca, 0xee, 0x78, 0x05, 0x6b,
		0x51, 0xe1, 0x59, 0xa3, 0xf2, 0x71, 0x56, 0x11, 0x6a, 0x89, 0x94, 0x65, 0x8c, 0xbb, 0x77, 0x3c,
		0x7b, 0x28, 0xab, 0xd2, 0x31, 0xde, 0xc4, 0x5f, 0xcc, 0xcf, 0x76, 0x2c, 0xb8, 0xd8, 0x2e, 0x36,
		0xdb, 0x69, 0xb3, 0x14, 0x95, 0xbe, 0x62, 0xa1, 0x3b, 0x16, 0x66, 0xe9, 0x5c, 0x6c, 0x6d, 0xad,
		0x37, 0x61, 0x4b, 0xb9, 0xe3, 0xba, 0xf1, 0xa0, 0x85, 0x83, 0xda, 0x47, 0xc5, 0xb0, 0x33, 0xfa,
		0x96, 0x6f, 0x6e, 0xc2, 0xf6, 0x50, 0xff, 0x5d, 0xa9, 0x8e, 0x17, 0x1b, 0x97, 0x7d, 0xec, 0x58,
		0xf7, 0x1f, 0xfb, 0x7c, 0x09, 0x0d, 0x7a, 0x67, 0x45, 0x87, 0xdc, 0xe8, 0x4f, 0x1d, 0x4e, 0x04,
		0xeb, 0xf8, 0xf3, 0x3e, 0x3d, 0xbd, 0x8a, 0x88, 0xdd, 0xcd, 0x0b, 0x13, 0x98, 0x02, 0x93, 0x80,
		0x90, 0xd0, 0x24, 0x34, 0xcb, 0xed, 0xf4, 0xce, 0x99, 0x10, 0x44, 0x40, 0x92, 0x3a, 0x01, 0x26,
		0x12, 0x1a, 0x48, 0x68, 0xf5, 0x81, 0x8b, 0xc7, 0xd6, 0x20, 0x0a, 0x08, 0x00, 0x4c, 0xd7, 0x74,
	}
	for i := range block {
		block[i] = invSbox[block[i]] // восстанавливаем исходный байт
	}
}

// преобразование R-функцией
func (k *Kuznechik) linearTransform(block []byte) {
	for i := 0; i < 16; i++ {
		block[i] ^= block[(i+1)%16] ^ block[(i+2)%16] ^ block[(i+3)%16] ^ block[(i+4)%16]
	}
}

// обратное преобразование
func (k *Kuznechik) inverseLinearTransform(block []byte) {
	for i := 15; i >= 0; i-- {
		block[i] ^= block[(i+1)%16] ^ block[(i+2)%16] ^ block[(i+3)%16] ^ block[(i+4)%16]
	}
}

// побитовый XOR между блоком и ключом раунда
func (k *Kuznechik) xorWithKey(block []byte, key [BlockSize]byte) {
	for i := range block {
		block[i] ^= key[i]
	}
}

// добавление константу к блоку
func (k *Kuznechik) addConstant(block []byte, constant []byte) {
	for i := range block {
		block[i] ^= constant[i]
	}
}

// размер блока шифрования
func (k *Kuznechik) BlockSize() int {
	return BlockSize
}

var selectedFilename string // имя файла, выбранное при скачивании
var mainWindow fyne.Window
var a fyne.App

const (
	maxUsernameLength = 20
	maxPasswordLength = 20
	maxFileSizeMB     = 940
)

// проверка логиа и пароля на соответствие требованиям
func validateCredentials(username, password string) error {
	if len(username) > maxUsernameLength {
		return fmt.Errorf("логин не должен превышать %d символов", maxUsernameLength)
	}
	if len(password) > maxPasswordLength {
		return fmt.Errorf("пароль не должен превышать %d символов", maxPasswordLength)
	}

	// запрещаем символы, потенциально опасные для SQL-инъекций
	sqlInjectionPattern := `[\;\-\"\'\%\=\$\<\>\&\|\+\*\?\{\}\~]`
	re := regexp.MustCompile(sqlInjectionPattern)

	if re.MatchString(username) {
		return fmt.Errorf("логин содержит недопустимые символы")
	}
	if re.MatchString(password) {
		return fmt.Errorf("пароль содержит недопустимые символы")
	}

	// проверка на пустоту
	if strings.TrimSpace(username) == "" {
		return fmt.Errorf("логин не может быть пустым")
	}
	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("пароль не может быть пустым")
	}

	return nil
}

// не превышает ли файл размер 940 МБ
func validateFileSize(filePath string) error {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("ошибка получения информации о файле: %v", err)
	}

	fileSizeMB := float64(fileInfo.Size()) / (1024 * 1024)
	if fileSizeMB > maxFileSizeMB {
		return fmt.Errorf("размер файла (%.2f МБ) превышает максимально допустимый (%d МБ)", fileSizeMB, maxFileSizeMB)
	}

	return nil
}

func encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := NewKuznechik(key) // создаём набор раундовых ключей
	if err != nil {
		return nil, err
	}

	//
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// генерируем случайный nonce (12 байт для GCM)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// шифруем: nonce + зашифрованные данные
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// расшифровывает данные, зашифрованные функцией encrypt
func decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := NewKuznechik(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("зашифрованные данные слишком короткие")
	}

	// Разделяем nonce и зашифрованный текст
	nonce, encrypted := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Расшифровываем
	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// сохраняет ключ шифрования по ID файла в файл keys.json
func saveKeyToFile(id string, key []byte) error {
	// Проверяем, что ID не содержит вредоносных символов
	if err := validateID(id); err != nil {
		return err
	}

	// Загружаем существующие ключи
	keys, err := loadKeysFromFile()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if keys == nil {
		keys = make(map[string]string) // Создаём новый, если файл не существует
	}

	// Кодируем ключ в base64 и сохраняем
	keys[id] = base64.StdEncoding.EncodeToString(key)

	// Сохраняем в файл
	file, err := os.Create("keys.json")
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewEncoder(file).Encode(keys)
}

// проверяем ID
func validateID(id string) error {
	sqlInjectionPattern := `[\;\-\-\"\'\%\=\$\$\<\>\&\|\+\*\?\$\$\{\}]`
	re := regexp.MustCompile(sqlInjectionPattern)

	if re.MatchString(id) {
		return fmt.Errorf("ID содержит недопустимые символы")
	}

	return nil
}

// загружаем все сохранённые ключи из файла keys.json
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

// извлекаем ключ по ID из файла keys.json
func getKeyByID(id string) ([]byte, error) {
	if err := validateID(id); err != nil {
		return nil, err
	}
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

// загружаем файл на сервер
func uploadFile(filePath, username, password string) {
	// проверка учётных данных
	if err := validateCredentials(username, password); err != nil {
		dialog.ShowError(err, mainWindow)
		return
	}

	// проверка размера файла
	if err := validateFileSize(filePath); err != nil {
		dialog.ShowError(err, mainWindow)
		return
	}

	// генерируем случайный 256-битный ключ
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		dialog.ShowError(fmt.Errorf("Ошибка генерации ключа: %v", err), mainWindow)
		return
	}

	// чтение файлв
	data, err := os.ReadFile(filePath)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Ошибка чтения файла: %v", err), mainWindow)
		return
	}

	// шифрование файла
	encryptedData, err := encrypt(data, key)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Ошибка шифрования: %v", err), mainWindow)
		return
	}

	// проверка имени на спецсимволы
	filename := filepath.Base(filePath)
	filename = strings.ReplaceAll(filename, "'", "")
	filename = strings.ReplaceAll(filename, "\"", "")
	filename = strings.ReplaceAll(filename, "\\", "")

	// HTTP-запрос
	req, err := http.NewRequest("POST", "https://"+serverip+"/upload?username="+username+"&filename="+filename, bytes.NewReader(encryptedData))
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

	// ответ от сервера
	var response struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		dialog.ShowError(fmt.Errorf("Ошибка декодирования ответа: %v", err), mainWindow)
		return
	}

	// сохранения ключа по ID
	if err := saveKeyToFile(response.ID, key); err != nil {
		dialog.ShowError(fmt.Errorf("Ошибка сохранения ключа: %v", err), mainWindow)
		return
	}

	dialog.ShowInformation("Успех", "Файл загружен, ID: "+response.ID, mainWindow)
}

// скачивавание и расшифрование зашифрованного файла
func downloadFile(id, username, password string) {
	// проверка учётных данных и ID
	if err := validateCredentials(username, password); err != nil {
		dialog.ShowError(err, mainWindow)
		return
	}

	if err := validateID(id); err != nil {
		dialog.ShowError(err, mainWindow)
		return
	}

	// ключ шифрования
	key, err := getKeyByID(id)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Ошибка получения ключа: %v", err), mainWindow)
		return
	}

	// запрос на скачивание
	req, err := http.NewRequest("GET", "https://"+serverip+"/download/"+id+"?username="+username, nil)
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

	// зашифрованные данные
	encryptedData, err := io.ReadAll(resp.Body)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Ошибка чтения данных: %v", err), mainWindow)
		return
	}

	// расшифровка
	decryptedData, err := decrypt(encryptedData, key)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Ошибка расшифрования: %v", err), mainWindow)
		return
	}

	// имя для сохранения
	filename := selectedFilename
	if filename == "" {
		filename = "downloaded_" + id + ".txt"
	}

	// окно выбора пути
	saveWindow := a.NewWindow("Сохранение файла")
	saveWindow.Resize(fyne.NewSize(800, 600))

	saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil {
			dialog.ShowError(fmt.Errorf("Ошибка сохранения файла: %v", err), saveWindow)
			saveWindow.Close()
			return
		}
		if writer == nil {
			saveWindow.Close()
			return
		}
		defer writer.Close()

		_, err = writer.Write(decryptedData)
		if err != nil {
			dialog.ShowError(fmt.Errorf("Ошибка записи файла: %v", err), saveWindow)
			saveWindow.Close()
			return
		}

		dialog.ShowInformation("Успех", "Файл успешно сохранен", saveWindow)
		saveWindow.Close()
	}, saveWindow)

	saveDialog.SetFileName(filename)
	saveDialog.Resize(fyne.NewSize(800, 600))
	saveDialog.Show()
	saveWindow.Show()
}

// структура для хранения информации о файле на сервере
type FileInfo struct {
	ID       string `json:"id"`
	Filename string `json:"filename"`
}

// запрос у сервера списка всех файлов
func listFiles(username, password string) ([]FileInfo, error) {
	if err := validateCredentials(username, password); err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", "https://"+serverip+"/listfiles?username="+username, nil)
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

// авторизация
func loginUser(username, password string) error {
	if err := validateCredentials(username, password); err != nil {
		return err
	}

	// JSON-запрос
	loginData := map[string]string{
		"username": username,
		"password": password,
	}
	jsonData, err := json.Marshal(loginData)
	if err != nil {
		return err
	}

	// POST-запрос
	resp, err := http.Post("https://"+serverip+"/login", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("неправильные учётные данные")
	}

	var response struct {
		Message string `json:"message"`
		Role    string `json:"role"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}

	return nil
}

func main() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	a = app.NewWithID("cloud-drive-client")
	mainWindow = a.NewWindow("Облачный диск")
	mainWindow.Resize(fyne.NewSize(600, 500))

	// поля ввода
	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("Логин")
	usernameEntry.OnChanged = func(s string) {
		if len(s) > maxUsernameLength {
			usernameEntry.SetText(s[:maxUsernameLength])
			dialog.ShowInformation("Предупреждение",
				fmt.Sprintf("Логин не может превышать %d символов", maxUsernameLength),
				mainWindow)
		}
	}

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Пароль")
	passwordEntry.OnChanged = func(s string) {
		if len(s) > maxPasswordLength {
			passwordEntry.SetText(s[:maxPasswordLength])
			dialog.ShowInformation("Предупреждение",
				fmt.Sprintf("Пароль не может превышать %d символов", maxPasswordLength),
				mainWindow)
		}
	}

	filePathEntry := widget.NewEntry()
	filePathEntry.SetPlaceHolder("Путь до файла для отправки")

	idEntry := widget.NewEntry()
	idEntry.SetPlaceHolder("ID файла для загрузки")

	// кнопки
	loginButton := widget.NewButton("Авторизация", func() {
		username := usernameEntry.Text
		password := passwordEntry.Text

		if err := validateCredentials(username, password); err != nil {
			dialog.ShowError(err, mainWindow)
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

		if err := validateCredentials(username, password); err != nil {
			dialog.ShowError(err, mainWindow)
			return
		}

		fileWindow := a.NewWindow("Выбор файла")
		fileWindow.Resize(fyne.NewSize(800, 600))

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

			if err := validateFileSize(filePath); err != nil {
				dialog.ShowError(err, mainWindow)
				fileWindow.Close()
				return
			}

			filePathEntry.SetText(filePath)
			uploadFile(filePath, username, password)
			fileWindow.Close()
		}, fileWindow)
		fileDialog.Resize(fyne.NewSize(800, 600))
		fileDialog.Show()
		fileWindow.Show()
	})

	listFilesButton := widget.NewButton("Список файлов", func() {
		username := usernameEntry.Text
		password := passwordEntry.Text

		if err := validateCredentials(username, password); err != nil {
			dialog.ShowError(err, mainWindow)
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
		selectDialog.Resize(fyne.NewSize(600, 400))
		selectDialog.Show()
	})

	downloadButton := widget.NewButton("Загрузка файлов", func() {
		username := usernameEntry.Text
		password := passwordEntry.Text
		id := idEntry.Text

		if err := validateCredentials(username, password); err != nil {
			dialog.ShowError(err, mainWindow)
			return
		}

		if err := validateID(id); err != nil {
			dialog.ShowError(err, mainWindow)
			return
		}

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
