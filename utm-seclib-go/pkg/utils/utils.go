package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/joho/godotenv"
	"github.com/nats-io/nats.go"
	geojson "github.com/paulmach/go.geojson"
	"github.com/royzah/utm-sec-lib/utm-seclib-go/pkg/types"
	"github.com/rs/zerolog/log"
)

var mu sync.Mutex

type LogLevel int
type LogCategory int

const (
	FlightplanCategory LogCategory = iota
	GeneralCategory
	ConnectionCategory
	KVCategory
	TelemetryCategory
	UTMCategory
)

const (
	InfoLevel LogLevel = iota
	DebugLevel
	WarnLevel
	ErrorLevel
)

func ConvertDateString(dateString, formatIn, formatOut string) (converted string, ConvertDateStringError error) {
	parsedTime, err := time.Parse(formatIn, dateString)
	if err != nil {
		return "", err
	}

	formattedDate := parsedTime.Format(formatOut)
	return formattedDate, nil
}

func AddDays(dateString string, days int, format string) (dateStringWithAddedDays string, AddDaysError error) {
	parsedTime, err := time.Parse(format, dateString)
	if err != nil {
		return "", err
	}

	newTime := parsedTime.Add(time.Duration(days) * 24 * time.Hour)
	newDateString := newTime.Format(format)

	return newDateString, nil
}

func GetEnvOrDefault(env, defaultValue string) (envOrDefault string) {
	if value := os.Getenv(env); value != "" {
		return value
	}

	return defaultValue
}

func GetBoolEnvOrDefault(env string, defaultValue bool) (envOrDefault bool) {
	if value := os.Getenv(env); value != "" {
		return strings.ToLower(value) == "true"
	}
	return defaultValue
}

func GetIntEnvOrDefault(env string, defaultValue int) int {
	envValue := os.Getenv(env)

	if envValue == "" {
		return defaultValue
	}

	intValue, err := strconv.Atoi(envValue)
	if err != nil {
		return defaultValue
	}

	return intValue
}

// UpdateValuesToBucket merges new JSON values with existing data in a KV store and returns the combined data
func UpdateValuesToBucket(js nats.JetStreamContext, bucketName string, key string, data map[string]interface{}) (combinedData interface{}, UpdateValuesToBucketError error) {
	mu.Lock()
	defer mu.Unlock()

	bucket, err := js.KeyValue(bucketName)
	if err != nil {
		cfg := nats.KeyValueConfig{
			Bucket:  bucketName,
			History: 1,
		}

		bucket, err = js.CreateKeyValue(&cfg)
		if err != nil {
			return nil, err
		}
	}

	existingData, _ := bucket.Get(key)

	combinedValues := make(map[string]interface{})

	if existingData != nil {
		if err := json.Unmarshal(existingData.Value(), &combinedValues); err != nil {
			return nil, err
		}
	}

	// Merge the new data into the combined values
	for k, v := range data {
		combinedValues[k] = v
	}

	combinedDataJSON, err := json.Marshal(combinedValues)
	if err != nil {
		return nil, err
	}

	if _, err := bucket.Put(key, combinedDataJSON); err != nil {
		return nil, err
	}

	return combinedValues, nil
}

func SetNewValuesToBucket(js nats.JetStreamContext, bucketName string, key string, data interface{}) error {
	mu.Lock()
	defer mu.Unlock()

	bucket, err := js.KeyValue(bucketName)
	if err != nil {
		cfg := nats.KeyValueConfig{
			Bucket:  bucketName,
			History: 1,
		}

		bucket, err = js.CreateKeyValue(&cfg)
		if err != nil {
			return err
		}
	}

	dataByte, err := json.Marshal(data)
	if err != nil {
		log.Error().Msgf("Failed to marshal json: %v", err)
	}

	if _, err := bucket.Put(key, dataByte); err != nil {
		return err
	}

	return nil
}

// GetValuesFromBucket gets values from a KV bucket by key
func GetValuesFromBucket(js nats.JetStreamContext, bucketName string, bucketKey string) (val []byte, GetValuesFromBucketError error) {
	mu.Lock()
	defer mu.Unlock()

	bucket, err := js.KeyValue(bucketName)
	if err != nil {
		return nil, err
	}

	values, err := bucket.Get(bucketKey)
	if err != nil {
		return nil, err
	}

	return values.Value(), nil
}

func CreateFolder(folderPath string) error {
	var fullPath string

	if strings.HasPrefix(folderPath, "./") {
		relativeFolderPath := strings.TrimPrefix(folderPath, "./")
		fullPath = path.Join(GetProjectRootPath(), relativeFolderPath)
	} else {
		fullPath = folderPath
	}

	return os.MkdirAll(fullPath, os.ModePerm)
}

func RemoveFile(filePath string) error {
	var fullPath string

	if strings.HasPrefix(filePath, "./") {
		relativeFolderPath := strings.TrimPrefix(filePath, "./")
		fullPath = path.Join(GetProjectRootPath(), relativeFolderPath)
	} else {
		fullPath = filePath
	}

	return os.Remove(fullPath)
}

func SaveBytesToFile(bytes []byte, filePath string) (byteCount int, err error) {
	var fullPath string

	if strings.HasPrefix(filePath, "./") {
		relativeFolderPath := strings.TrimPrefix(filePath, "./")
		fullPath = filepath.Join(GetProjectRootPath(), relativeFolderPath)
	} else {
		fullPath = filePath
	}

	file, err := os.Create(fullPath) // #nosec G304
	if err != nil {
		return 0, err
	}

	defer file.Close()

	return file.Write(bytes)
}

func GetProjectRootPath() string {
	_, b, _, _ := runtime.Caller(0)
	return filepath.Join(b, "..", "..", "..", "/")
}

func LoadBytesFromFile(filePath string) (bytes []byte, err error) {

	var fullPath string

	if strings.HasPrefix(filePath, "./") {
		relativeFolderPath := strings.TrimPrefix(filePath, "./")
		fullPath = filepath.Join(GetProjectRootPath(), relativeFolderPath)
	} else {
		fullPath = filePath
	}

	file, err := os.Open(fullPath) // #nosec G304
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

func LoadEnv(filename string) error {

	fullPath := filepath.Join(GetProjectRootPath(), filename)

	loadEnvError := godotenv.Load(fullPath)

	if loadEnvError != nil {
		return fmt.Errorf("error loading %s. environment files should be placed in drone-utm project folder (.env for production, .env.test for testing)", filename)
	}

	return nil
}

func GeoJSONPolygonToPoints(gj *geojson.Geometry) []types.Point {
	var points []types.Point
	for _, coords := range gj.Polygon {
		for _, coord := range coords {
			points = append(points, types.Point{
				X: coord[1],
				Y: coord[0],
				Z: 2.5,
			})
		}
	}

	return points
}

func GetReaderFromJsonString(jsonStr string) (io.ReadCloser, error) {
	if !json.Valid([]byte(jsonStr)) {
		return nil, fmt.Errorf("invalid json string")
	}

	jsonBytes, _ := json.Marshal([]byte(jsonStr))

	return io.NopCloser(strings.NewReader(string(jsonBytes))), nil
}

/*
Logs messages in a clear way.
fields:
1: Mission ID
2: Device ID
3: Flightplan ID
*/
func LogMessage(msg string, logLevel LogLevel, logCategory LogCategory, fields ...string) {
	var logMsg string
	//infoColor := color.New(color.FgHiGreen).SprintFunc()
	warnColor := color.New(color.FgYellow).SprintFunc()
	errorColor := color.New(color.FgHiRed).SprintFunc()
	debugColor := color.New(color.FgHiYellow).SprintFunc()

	switch len(fields) {
	case 0:
		logMsg = fmt.Sprintf("%s\n", msg)
	case 1:
		logMsg = fmt.Sprintf("%s - %s\n", fields[0], msg)
	case 2:
		logMsg = fmt.Sprintf("%s - %s - %s\n", fields[0], fields[1], msg)
	case 3:
		logMsg = fmt.Sprintf("%s - %s - %s - %s\n", fields[0], fields[1], fields[2], msg)
	}

	switch logLevel {
	case InfoLevel:
		log.Info().Msgf("<%s> - %s", logCategory.Color()(logCategory.String()), logMsg)
	case DebugLevel:
		log.Debug().Msgf("<%s> - %s", logCategory.Color()(logCategory.String()), debugColor(logMsg))
	case WarnLevel:
		log.Warn().Msgf("<%s> - %s", logCategory.Color()(logCategory.String()), warnColor(logMsg))
	case ErrorLevel:
		log.Error().Msgf("<%s> - %s", logCategory.Color()(logCategory.String()), errorColor(logMsg))
	}
}

func (lc LogCategory) String() string {
	switch lc {
	case FlightplanCategory:
		return "Flightplans"
	case GeneralCategory:
		return "General"
	case ConnectionCategory:
		return "Connections"
	case KVCategory:
		return "KV-Store"
	case TelemetryCategory:
		return "Telemetry"
	case UTMCategory:
		return "UTM"
	default:
		return "Unknown"
	}
}

func (lc LogCategory) Color() func(a ...interface{}) string {
	switch lc {
	case FlightplanCategory:
		return color.New(color.FgHiBlue).SprintFunc()
	case ConnectionCategory:
		return color.New(color.FgHiGreen).SprintFunc()
	case KVCategory:
		return color.New(color.FgHiMagenta).SprintFunc()
	case TelemetryCategory:
		return color.New(color.FgHiCyan).SprintFunc()
	case UTMCategory:
		return color.New(color.FgHiYellow).SprintFunc()
	default:
		return color.New(color.FgWhite).SprintFunc()
	}
}
