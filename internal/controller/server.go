package controller

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultJSONBodyLimit = int64(64 << 10)
	policyJSONBodyLimit  = int64(256 << 10)
	reportJSONBodyLimit  = int64(1 << 20)
)

var (
	errBodyTooLarge     = errors.New("request body exceeds limit")
	errUnsupportedMedia = errors.New("request content type must be application/json")
)

type Server struct {
	store      *Store
	principals *PrincipalSet
	signer     *Signer
	now        func() time.Time
	handler    http.Handler
}

func NewServer(store *Store, principals *PrincipalSet, signer *Signer) (*Server, error) {
	if store == nil || store.db == nil {
		return nil, errors.New("controller store is required")
	}
	if principals == nil || len(principals.principals) == 0 {
		return nil, errors.New("controller principals are required")
	}
	if signer == nil || len(signer.privateKey) == 0 {
		return nil, errors.New("controller signer is required")
	}
	server := &Server{
		store:      store,
		principals: principals,
		signer:     signer,
		now:        time.Now,
	}
	server.handler = server.routes()
	return server, nil
}

func (server *Server) Handler() http.Handler {
	return server.handler
}

func (server *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", server.health)

	mux.HandleFunc("POST /v1/agent/enroll", server.enroll)
	mux.HandleFunc("POST /v1/agent/heartbeat", server.withAgent(server.heartbeat))
	mux.HandleFunc("GET /v1/agent/policy", server.withAgent(server.fetchPolicy))
	mux.HandleFunc("POST /v1/agent/reports", server.withAgent(server.syncReport))
	mux.HandleFunc(
		"POST /v1/agent/credentials/rotate",
		server.withAgent(server.rotateCredential),
	)

	mux.HandleFunc(
		"POST /v1/admin/enrollment-tokens",
		server.withPrincipal(RoleOperator, server.createEnrollmentToken),
	)
	mux.HandleFunc(
		"GET /v1/admin/devices",
		server.withPrincipal(RoleViewer, server.listDevices),
	)
	mux.HandleFunc(
		"POST /v1/admin/devices/{deviceID}/revoke",
		server.withPrincipal(RoleAdmin, server.revokeDevice),
	)
	mux.HandleFunc(
		"PUT /v1/admin/devices/{deviceID}/group",
		server.withPrincipal(RoleOperator, server.assignDeviceGroup),
	)
	mux.HandleFunc(
		"GET /v1/admin/findings",
		server.withPrincipal(RoleViewer, server.listFindings),
	)
	mux.HandleFunc(
		"GET /v1/admin/audit",
		server.withPrincipal(RoleAdmin, server.listAudit),
	)
	mux.HandleFunc(
		"GET /v1/admin/policies",
		server.withPrincipal(RoleViewer, server.listPolicies),
	)
	mux.HandleFunc(
		"POST /v1/admin/policies",
		server.withPrincipal(RoleOperator, server.createPolicy),
	)
	mux.HandleFunc(
		"GET /v1/admin/policies/{policyID}",
		server.withPrincipal(RoleViewer, server.getPolicy),
	)
	mux.HandleFunc(
		"PUT /v1/admin/policies/{policyID}",
		server.withPrincipal(RoleOperator, server.updatePolicy),
	)
	mux.HandleFunc(
		"DELETE /v1/admin/policies/{policyID}",
		server.withPrincipal(RoleOperator, server.deletePolicy),
	)
	mux.HandleFunc(
		"GET /v1/admin/groups/{group}/policy",
		server.withPrincipal(RoleViewer, server.getGroupPolicy),
	)
	mux.HandleFunc(
		"PUT /v1/admin/groups/{group}/policy",
		server.withPrincipal(RoleOperator, server.assignGroupPolicy),
	)
	mux.HandleFunc(
		"DELETE /v1/admin/groups/{group}/policy",
		server.withPrincipal(RoleOperator, server.unassignGroupPolicy),
	)
	return securityHeaders(mux)
}

func (server *Server) health(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

type enrollmentRequest struct {
	EnrollmentToken string         `json:"enrollment_token"`
	Device          DeviceMetadata `json:"device"`
}

func (server *Server) enroll(writer http.ResponseWriter, request *http.Request) {
	var body enrollmentRequest
	if err := decodeRequestJSON(writer, request, defaultJSONBodyLimit, &body); err != nil {
		writeDecodeError(writer, err)
		return
	}
	grant, _, err := server.store.Enroll(
		request.Context(),
		body.EnrollmentToken,
		body.Device,
		server.now(),
	)
	if err != nil {
		if errors.Is(err, ErrUnauthenticated) {
			writeUnauthorized(writer)
			return
		}
		writeStoreError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, grant)
}

func (server *Server) heartbeat(
	writer http.ResponseWriter,
	request *http.Request,
	device Device,
) {
	var metadata DeviceMetadata
	if err := decodeRequestJSON(writer, request, defaultJSONBodyLimit, &metadata); err != nil {
		writeDecodeError(writer, err)
		return
	}
	if err := server.store.Heartbeat(
		request.Context(),
		device.ID,
		metadata,
		server.now(),
	); err != nil {
		writeStoreError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) fetchPolicy(
	writer http.ResponseWriter,
	request *http.Request,
	device Device,
) {
	document, err := server.store.PolicyForDevice(request.Context(), device.ID)
	if err != nil {
		writeStoreError(writer, err)
		return
	}
	signed, err := server.signer.Sign(document)
	if err != nil {
		writeStoreError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, signed)
}

func (server *Server) syncReport(
	writer http.ResponseWriter,
	request *http.Request,
	device Device,
) {
	var report ReportSync
	if err := decodeRequestJSON(writer, request, reportJSONBodyLimit, &report); err != nil {
		writeDecodeError(writer, err)
		return
	}
	if err := server.store.SyncReport(
		request.Context(),
		device.ID,
		report,
		server.now(),
	); err != nil {
		writeStoreError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]int{"accepted": len(report.Findings)})
}

func (server *Server) rotateCredential(
	writer http.ResponseWriter,
	request *http.Request,
	device Device,
) {
	if !requireEmptyBody(writer, request) {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	credential, err := server.store.RotateDeviceCredential(
		request.Context(),
		device.ID,
		server.now(),
	)
	if err != nil {
		writeStoreError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{
		"device_id":         device.ID,
		"device_credential": credential,
	})
}

type createEnrollmentTokenRequest struct {
	Group      string `json:"group"`
	TTLSeconds uint32 `json:"ttl_seconds"`
}

func (server *Server) createEnrollmentToken(
	writer http.ResponseWriter,
	request *http.Request,
	principal Principal,
) {
	var body createEnrollmentTokenRequest
	if err := decodeRequestJSON(writer, request, defaultJSONBodyLimit, &body); err != nil {
		writeDecodeError(writer, err)
		return
	}
	token, expiresAt, err := server.store.CreateEnrollmentToken(
		request.Context(),
		principal.ID,
		body.Group,
		time.Duration(body.TTLSeconds)*time.Second,
		server.now(),
	)
	if err != nil {
		writeStoreError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{
		"enrollment_token": token,
		"expires_at":       expiresAt,
	})
}

func (server *Server) listDevices(
	writer http.ResponseWriter,
	request *http.Request,
	_ Principal,
) {
	limit, ok := queryInteger(writer, request, "limit", 0)
	if !ok {
		return
	}
	devices, err := server.store.ListDevices(request.Context(), limit)
	if err != nil {
		writeStoreError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"devices": devices})
}

func (server *Server) revokeDevice(
	writer http.ResponseWriter,
	request *http.Request,
	principal Principal,
) {
	if !requireEmptyBody(writer, request) {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := server.store.RevokeDevice(
		request.Context(),
		principal.ID,
		request.PathValue("deviceID"),
		server.now(),
	); err != nil {
		writeStoreError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

type groupRequest struct {
	Group string `json:"group"`
}

func (server *Server) assignDeviceGroup(
	writer http.ResponseWriter,
	request *http.Request,
	principal Principal,
) {
	var body groupRequest
	if err := decodeRequestJSON(writer, request, defaultJSONBodyLimit, &body); err != nil {
		writeDecodeError(writer, err)
		return
	}
	if err := server.store.AssignDeviceGroup(
		request.Context(),
		principal.ID,
		request.PathValue("deviceID"),
		body.Group,
		server.now(),
	); err != nil {
		writeStoreError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) listFindings(
	writer http.ResponseWriter,
	request *http.Request,
	_ Principal,
) {
	limit, ok := queryInteger(writer, request, "limit", 0)
	if !ok {
		return
	}
	findings, err := server.store.ListFindings(request.Context(), limit)
	if err != nil {
		writeStoreError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"findings": findings})
}

func (server *Server) listAudit(
	writer http.ResponseWriter,
	request *http.Request,
	_ Principal,
) {
	limit, ok := queryInteger(writer, request, "limit", 0)
	if !ok {
		return
	}
	after, ok := queryInteger(writer, request, "after", 0)
	if !ok {
		return
	}
	entries, err := server.store.ListAudit(request.Context(), int64(after), limit)
	if err != nil {
		writeStoreError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"audit": entries})
}

func (server *Server) listPolicies(
	writer http.ResponseWriter,
	request *http.Request,
	_ Principal,
) {
	limit, ok := queryInteger(writer, request, "limit", 0)
	if !ok {
		return
	}
	policies, err := server.store.ListPolicies(request.Context(), limit)
	if err != nil {
		writeStoreError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"policies": policies})
}

func (server *Server) createPolicy(
	writer http.ResponseWriter,
	request *http.Request,
	principal Principal,
) {
	var document PolicyDocument
	if err := decodeRequestJSON(writer, request, policyJSONBodyLimit, &document); err != nil {
		writeDecodeError(writer, err)
		return
	}
	if err := server.store.CreatePolicy(
		request.Context(),
		principal.ID,
		document,
		server.now(),
	); err != nil {
		writeStoreError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, document)
}

func (server *Server) getPolicy(
	writer http.ResponseWriter,
	request *http.Request,
	_ Principal,
) {
	document, err := server.store.GetPolicy(
		request.Context(),
		request.PathValue("policyID"),
	)
	if err != nil {
		writeStoreError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, document)
}

func (server *Server) updatePolicy(
	writer http.ResponseWriter,
	request *http.Request,
	principal Principal,
) {
	var document PolicyDocument
	if err := decodeRequestJSON(writer, request, policyJSONBodyLimit, &document); err != nil {
		writeDecodeError(writer, err)
		return
	}
	if document.ID != request.PathValue("policyID") {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := server.store.UpdatePolicy(
		request.Context(),
		principal.ID,
		document,
		server.now(),
	); err != nil {
		writeStoreError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, document)
}

func (server *Server) deletePolicy(
	writer http.ResponseWriter,
	request *http.Request,
	principal Principal,
) {
	if !requireEmptyBody(writer, request) {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := server.store.DeletePolicy(
		request.Context(),
		principal.ID,
		request.PathValue("policyID"),
		server.now(),
	); err != nil {
		writeStoreError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) getGroupPolicy(
	writer http.ResponseWriter,
	request *http.Request,
	_ Principal,
) {
	document, err := server.store.PolicyForGroup(
		request.Context(),
		request.PathValue("group"),
	)
	if err != nil {
		writeStoreError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, document)
}

type policyAssignmentRequest struct {
	PolicyID string `json:"policy_id"`
}

func (server *Server) assignGroupPolicy(
	writer http.ResponseWriter,
	request *http.Request,
	principal Principal,
) {
	var body policyAssignmentRequest
	if err := decodeRequestJSON(writer, request, defaultJSONBodyLimit, &body); err != nil {
		writeDecodeError(writer, err)
		return
	}
	if err := server.store.AssignGroupPolicy(
		request.Context(),
		principal.ID,
		request.PathValue("group"),
		body.PolicyID,
		server.now(),
	); err != nil {
		writeStoreError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) unassignGroupPolicy(
	writer http.ResponseWriter,
	request *http.Request,
	principal Principal,
) {
	if !requireEmptyBody(writer, request) {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := server.store.UnassignGroupPolicy(
		request.Context(),
		principal.ID,
		request.PathValue("group"),
		server.now(),
	); err != nil {
		writeStoreError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) withPrincipal(
	required Role,
	next func(http.ResponseWriter, *http.Request, Principal),
) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, authenticated := server.principals.AuthenticateBearer(
			request.Header.Get("Authorization"),
		)
		if !authenticated {
			writeUnauthorized(writer)
			return
		}
		if !principal.Role.Allows(required) {
			writeAPIError(writer, http.StatusForbidden, "forbidden")
			return
		}
		next(writer, request, principal)
	}
}

func (server *Server) withAgent(
	next func(http.ResponseWriter, *http.Request, Device),
) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		credential, validFormat := bearerToken(request.Header.Get("Authorization"))
		device, err := server.store.AuthenticateDevice(
			request.Context(),
			request.Header.Get("X-Device-ID"),
			credential,
		)
		if err != nil || !validFormat {
			writeUnauthorized(writer)
			return
		}
		next(writer, request, device)
	}
}

func bearerToken(header string) (string, bool) {
	if len(header) <= len("Bearer ") ||
		len(header) > len("Bearer ")+maxBearerTokenBytes ||
		!strings.HasPrefix(header, "Bearer ") {
		return "", false
	}
	token := header[len("Bearer "):]
	if strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}
	return token, true
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Security-Policy", "default-src 'none'")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(writer, request)
	})
}

func decodeRequestJSON(
	writer http.ResponseWriter,
	request *http.Request,
	limit int64,
	destination any,
) error {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errUnsupportedMedia
	}
	if request.ContentLength > limit {
		return errBodyTooLarge
	}
	request.Body = http.MaxBytesReader(writer, request.Body, limit)
	err = decodeStrictReader(request.Body, destination)
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		return errBodyTooLarge
	}
	return err
}

func requireEmptyBody(writer http.ResponseWriter, request *http.Request) bool {
	request.Body = http.MaxBytesReader(writer, request.Body, 1)
	var buffer [1]byte
	count, err := request.Body.Read(buffer[:])
	return count == 0 && errors.Is(err, io.EOF)
}

func writeDecodeError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errBodyTooLarge):
		writeAPIError(writer, http.StatusRequestEntityTooLarge, "request_too_large")
	case errors.Is(err, errUnsupportedMedia):
		writeAPIError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type")
	default:
		writeAPIError(writer, http.StatusBadRequest, "invalid_request")
	}
}

func writeStoreError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidInput):
		writeAPIError(writer, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, ErrNotFound):
		writeAPIError(writer, http.StatusNotFound, "not_found")
	case errors.Is(err, ErrConflict):
		writeAPIError(writer, http.StatusConflict, "conflict")
	case errors.Is(err, ErrUnauthenticated):
		writeUnauthorized(writer)
	default:
		writeAPIError(writer, http.StatusInternalServerError, "internal_error")
	}
}

func writeUnauthorized(writer http.ResponseWriter) {
	writer.Header().Set("WWW-Authenticate", `Bearer realm="oh-my-safety-controller"`)
	writeAPIError(writer, http.StatusUnauthorized, "unauthorized")
}

func writeAPIError(writer http.ResponseWriter, status int, code string) {
	writeJSON(writer, status, map[string]string{"error": code})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func queryInteger(
	writer http.ResponseWriter,
	request *http.Request,
	name string,
	fallback int,
) (int, bool) {
	values, present := request.URL.Query()[name]
	if !present {
		return fallback, true
	}
	if len(values) != 1 || values[0] == "" {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request")
		return 0, false
	}
	value, err := strconv.Atoi(values[0])
	if err != nil || value < 0 {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request")
		return 0, false
	}
	return value, true
}

func ValidateListenConfiguration(listenAddress, certificatePath, keyPath string) error {
	host, port, err := net.SplitHostPort(listenAddress)
	if err != nil || port == "" {
		return errors.New("listen address must be in host:port form")
	}
	hasCertificate := strings.TrimSpace(certificatePath) != ""
	hasKey := strings.TrimSpace(keyPath) != ""
	if hasCertificate != hasKey {
		return errors.New("TLS certificate and key must be provided together")
	}
	if !isLoopbackHost(host) && !hasCertificate {
		return errors.New("TLS is required for non-loopback listeners")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func NewHTTPServer(listenAddress string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              listenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
}

func EndpointSummary() []string {
	return []string{
		"GET /healthz",
		"POST /v1/agent/enroll",
		"POST /v1/agent/heartbeat",
		"GET /v1/agent/policy",
		"POST /v1/agent/reports",
		"POST /v1/agent/credentials/rotate",
		"POST /v1/admin/enrollment-tokens",
		"GET /v1/admin/devices",
		"POST /v1/admin/devices/{deviceID}/revoke",
		"PUT /v1/admin/devices/{deviceID}/group",
		"GET /v1/admin/findings",
		"GET /v1/admin/audit",
		"GET /v1/admin/policies",
		"POST /v1/admin/policies",
		"GET /v1/admin/policies/{policyID}",
		"PUT /v1/admin/policies/{policyID}",
		"DELETE /v1/admin/policies/{policyID}",
		"GET /v1/admin/groups/{group}/policy",
		"PUT /v1/admin/groups/{group}/policy",
		"DELETE /v1/admin/groups/{group}/policy",
	}
}

func (server *Server) String() string {
	return fmt.Sprintf("organization controller (%d routes)", len(EndpointSummary()))
}
