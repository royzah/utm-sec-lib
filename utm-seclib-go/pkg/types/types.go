package types

import (
	"encoding/json"
	"time"

	geojson "github.com/paulmach/go.geojson"
)

type MissionRequest struct {
	MissionId string                 `json:"mission_id"`
	Devices   []MissionRequestDevice `json:"devices"`
}

type MissionRequestDevice struct {
	DeviceId    string          `json:"device_id"`
	Positions   []UtmCoordinate `json:"positions"`
	StartTime   string          `json:"start_time"`
	EndTime     string          `json:"end_time"`
	MinAltitude int             `json:"min_altitude"`
	MaxAltitude int             `json:"max_altitude"`
}

type FlightPlanResponse struct {
	ClientType        string                    `json:"client_type"`
	MissionId         string                    `json:"mission_id"`
	DeviceId          string                    `json:"device_id"`
	FlightPlanId      string                    `json:"flightplan_id"`
	Name              string                    `json:"name"`
	Author            string                    `json:"author"`
	StartDatetime     string                    `json:"start_datetime"`
	EndDatetime       string                    `json:"end_datetime"`
	FeatureCollection geojson.FeatureCollection `json:"feature_collection"`
	Status            int                       `json:"status"`
	ErrorMessage      string                    `json:"error_message"`
}

type GeofenceResponse struct {
	ClientType        string                    `json:"client_type"`
	GeofenceId        string                    `json:"geofence_id"`
	Name              string                    `json:"name"`
	Author            string                    `json:"author"`
	StartDatetime     string                    `json:"start_datetime"`
	EndDatetime       string                    `json:"end_datetime"`
	FeatureCollection geojson.FeatureCollection `json:"feature_collection"`
	LowerLimit        string                    `json:"lower_limit"`
	UpperLimit        string                    `json:"upper_limit"`
	ErrorMessage      string                    `json:"error_message"`
}

type FlightPlanActivation struct {
	Devices   []DeviceWithGeojson `json:"devices"`
	Submitter Submitter           `json:"submitter"`
	MissionId string              `json:"mission_id"`
}

type DeviceWithGeojson struct {
	DeviceId string                    `json:"device_id"`
	Geojson  geojson.FeatureCollection `json:"geojson"`
}

type Point struct {
	X float64 `yaml:"x"`
	Y float64 `yaml:"y"`
	Z float64 `yaml:"z"`
}

type FlightActivation struct {
	FlightPlanId string `json:"flight_plan_id"`
	MissionId    string `json:"mission_id"`
}

type Submitter struct {
	SubmittedBy      string `json:"submitted_by"`
	OriginatingParty string `json:"originating_party"`
}

type OperationalIntent struct {
	Volumes           []any `json:"volumes"`
	OffNominalVolumes []any `json:"off_nominal_volumes"`
	Priority          int   `json:"priority"`
}

type TimeStamp struct {
	Value  string `json:"value"`
	Format string `json:"format"`
}

type UtmCoordinate struct {
	Alt           float64 `json:"alt"`
	Lat           float64 `json:"lat"`
	Lon           float64 `json:"lon"`
	IsDevicePoint bool    `json:"isDevicePoint,omitempty"`
}

type Signal struct {
	ID    string
	Value interface{}
}

type JWSHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type JWSSignature struct {
	Header    string `json:"header"`
	Body      string `json:"body"`
	Signature string `json:"signature"`
}

type FlightKvInfo struct {
	DeviceID  string `json:"device_id"`
	MissionID string `json:"mission_id"`
}

type MissionRequestData struct {
	Mission     string          `json:"mission"`
	Device      string          `json:"device_id"`
	Positions   []UtmCoordinate `json:"positions"`
	StartTime   string          `json:"start_time"`
	EndTime     string          `json:"end_time"`
	MinAltitude int             `json:"min_altitude"`
	MaxAltitude int             `json:"max_altitude"`
	Submitter   string          `json:"submitter"`
	Originating string          `json:"originating_party"`
}

type SignatureBase struct {
	Method          string
	Authority       string
	TargetURI       string
	ContentDigest   string // Optional field, only for POST requests
	SignatureParams string
	Algorithm       string
	KeyID           string
	Created         int64
}

type Coordinate struct {
	Lat float64 `json:"lat"`
	Lng float64 `json:"lng"`
}

type ConformanceMessage struct {
	Body      string `json:"body"`
	RawBody   string `json:"raw_body"`
	Level     string `json:"level"`
	Timestamp string `json:"timestamp"`
	DeviceId  string `json:"device_id"`
	MissionId string `json:"mission_id"`
}

type MissionCommandMessage struct {
	Type string          `json:"type"`
	Body json.RawMessage `json:"body"`
}

type WeatherDataQuery struct {
	Longitude float64 `json:"longitude"`
	Latitude  float64 `json:"latitude"`
	StartDate string  `json:"start_date"`
	EndDate   string  `json:"end_date"`
}

type WeatherHourlyUnits struct {
	Time             string `json:"time"`
	Temperature2m    string `json:"temperature_2m"`
	Showers          string `json:"showers"`
	Windspeed10m     string `json:"windspeed_10m"`
	Winddirection10m string `json:"winddirection_10m"`
	Windgusts10m     string `json:"windgusts_10m"`
}

type WeatherHourlyData struct {
	Time             []string  `json:"time"`
	Temperature2m    []float64 `json:"temperature_2m"`
	Showers          []float64 `json:"showers"`
	Windspeed10m     []float64 `json:"windspeed_10m"`
	Winddirection10m []float64 `json:"winddirection_10m"`
	Windgusts10m     []float64 `json:"windgusts_10m"`
}

type WeatherDataResult struct {
	Latitude             float64            `json:"latitude"`
	Longitude            float64            `json:"longitude"`
	GenerationtimeMs     float64            `json:"generationtime_ms"`
	UtcOffsetSeconds     int                `json:"utc_offset_seconds"`
	Timezone             string             `json:"timezone"`
	TimezoneAbbreviation string             `json:"timezone_abbreviation"`
	Elevation            float64            `json:"elevation"`
	HourlyUnits          WeatherHourlyUnits `json:"hourly_units"`
	Hourly               WeatherHourlyData  `json:"hourly"`
}

type AbortRequestDeviceData struct {
	DeviceId string  `json:"device_id"`
	Altitude float64 `json:"altitude"`
}

type ExtractedProperties struct {
	PublicKeyPem  string
	Signature     string
	SignatureBase string
}

type IETFRequestParams struct {
	Method      string `json:"method"`
	URL         string `json:"url"`
	Body        string `json:"body"`
	BearerToken string `json:"bearerToken,omitempty"`
}

type IETFRequestResult struct {
	ContentDigest string `json:"contentDigest"`
	SigInput      string `json:"sigInput"`
	CertBase64    string `json:"certBase64"`
	Signature     string `json:"signature"`
	AuthHeader    string `json:"authHeader"`
}

type SignedRequest struct {
	Method  string
	URL     string
	Headers map[string]string
}

type IETFRequestConfig struct {
	Method     string        `json:"method"`
	Timeout    time.Duration `json:"timeout"`
	Retries    int           `json:"retries"`
	RetryDelay time.Duration `json:"retryDelay"`
}

type SignatureCoveredContent struct {
	Authority       string
	Method          string
	TargetUri       string
	SignatureParams string
	ContentDigest   string
}

type HttpsSignatureComponents struct {
	Method          string `json:"@method"`
	Authority       string `json:"@authority"`
	TargetUri       string `json:"@target-uri"`
	ContentDigest   string `json:"content-digest"`
	SignatureParams string `json:"@signature-params"`
}

type IETFSignedResponse struct {
	Headers ResponseHeaders
	Config  ResponseConfig
}

type ResponseHeaders struct {
	CertificateBundle string
	Signature         string
	SignatureInput    string
	ContentDigest     string
}

type ResponseConfig struct {
	URL    string
	Method string
}
