package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	httpSwagger "github.com/swaggo/http-swagger"
)

// In-memory fake data store
type store struct {
	mu          sync.RWMutex
	flavors     map[string]Flavor
	images      map[string]Image
	volumes     map[string]Volume
	floatingIPs map[string]FloatingIP
	keypairs    map[string]Keypair
	networks    map[string]Network
	servers     map[string]Server
	users       map[string]StoredUser // username -> user
	tokens      map[string]Token      // token ID -> token
}

var s *store

var (
	errServerNotFound          = errors.New("server not found")
	errVolumeNotFound          = errors.New("volume not found")
	errVolumeAlreadyAttached   = errors.New("volume already attached")
	errVolumeNotAttached       = errors.New("volume not attached to server")
	errFloatingIPNotFound      = errors.New("floating IP not found")
	errFloatingIPInUse         = errors.New("floating IP already in use")
	errFloatingIPNotAssociated = errors.New("floating IP not associated with server")
	errInvalidCredentials      = errors.New("invalid credentials")
	errUnauthorized            = errors.New("unauthorized")
	errTokenNotFound           = errors.New("token not found")
	errTokenExpired            = errors.New("token expired")
)

func init() {
	rand.Seed(time.Now().UnixNano())

	s = &store{
		flavors: map[string]Flavor{
			"1": {ID: "1", Name: "m1.small", VCPUs: 1, RAM: 2048, Disk: 20},
			"2": {ID: "2", Name: "m1.medium", VCPUs: 2, RAM: 4096, Disk: 40},
			"3": {ID: "3", Name: "m1.large", VCPUs: 4, RAM: 8192, Disk: 80},
		},
		images: map[string]Image{
			"img-ubuntu": {ID: "img-ubuntu", Name: "Ubuntu 22.04", OSDiskSize: 20, OS: "linux", Description: "Ubuntu 22.04 LTS"},
			"img-centos": {ID: "img-centos", Name: "CentOS 9", OSDiskSize: 20, OS: "linux", Description: "CentOS Stream 9"},
		},
		volumes: map[string]Volume{
			"vol-1": {ID: "vol-1", Name: "db-data", SizeGB: 20, Status: "available"},
			"vol-2": {ID: "vol-2", Name: "logs", SizeGB: 50, Status: "available"},
		},
		floatingIPs: map[string]FloatingIP{
			"fip-1": {ID: "fip-1", Address: "192.0.2.101"},
			"fip-2": {ID: "fip-2", Address: "192.0.2.102"},
		},
		keypairs: map[string]Keypair{
			"demo": {
				Name:        "demo",
				PublicKey:   "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsDemoKey mock-user",
				Fingerprint: "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
				UserID:      "user-1",
			},
		},
		networks: map[string]Network{
			"net-1": {ID: "net-1", Name: "public", CIDR: "192.0.2.0/24"},
			"net-2": {ID: "net-2", Name: "private", CIDR: "10.0.0.0/24"},
		},
		servers: make(map[string]Server),
		users: map[string]StoredUser{
			"admin": {
				ID:          "user-admin",
				Name:        "admin",
				Password:    "admin123",
				DomainID:    "default",
				ProjectID:   "project-admin",
				ProjectName: "admin",
				Role:        "admin",
			},
			"demo": {
				ID:          "user-demo",
				Name:        "demo",
				Password:    "demo123",
				DomainID:    "default",
				ProjectID:   "project-demo",
				ProjectName: "demo",
				Role:        "member",
			},
		},
		tokens: make(map[string]Token),
	}
}

func main() {
	addr := flag.String("addr", ":5000", "address to listen on (e.g. :5000)")
	flag.Parse()

	mux := http.NewServeMux()

	// Serve OpenAPI spec
	mux.HandleFunc("/openapi.yaml", handleOpenAPISpec)

	// Swagger UI - configure to use our openapi.yaml
	mux.HandleFunc("/swagger/", httpSwagger.Handler(httpSwagger.URL("/openapi.yaml")))

	// Keystone-like auth (no auth required)
	mux.HandleFunc("/v3/auth/tokens", handleAuthTokens)

	// Nova/Cinder/Network-like endpoints (require authentication)
	mux.HandleFunc("/v2.1/flavors", requireAuth(handleFlavors))
	mux.HandleFunc("/v2.1/flavors/detail", requireAuth(handleFlavorsDetail))
	mux.HandleFunc("/v2.1/images", requireAuth(handleImagesList))
	mux.HandleFunc("/v2.1/volumes", requireAuth(handleVolumesList))
	mux.HandleFunc("/v2.1/floatingips", requireAuth(handleFloatingIPs))
	mux.HandleFunc("/v2.1/os-keypairs", requireAuth(handleKeypairs))
	mux.HandleFunc("/v2.1/networks", requireAuth(handleNetworks))
	mux.HandleFunc("/v2.1/servers", requireAuth(handleServersRoot))
	mux.HandleFunc("/v2.1/servers/", requireAuth(handleServerByID))

	log.Printf("Fake OpenStack server listening on %s", *addr)
	log.Printf("Swagger UI available at http://localhost%s/swagger/", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

// --- Handlers ---

// handleOpenAPISpec serves the OpenAPI specification file
func handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Try to read openapi.yaml from the same directory as the binary or current working directory
	paths := []string{
		"./openapi.yaml",
		"../openapi.yaml",
		"../../openapi.yaml",
		"/app/openapi.yaml",
	}

	var specData []byte
	var err error
	for _, path := range paths {
		specData, err = os.ReadFile(path)
		if err == nil {
			break
		}
	}

	if err != nil {
		// If file not found, try to find it relative to the executable
		exePath, exeErr := os.Executable()
		if exeErr == nil {
			exeDir := filepath.Dir(exePath)
			specPath := filepath.Join(exeDir, "openapi.yaml")
			specData, err = os.ReadFile(specPath)
		}
	}

	if err != nil {
		http.Error(w, "OpenAPI spec not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	w.Write(specData)
}

// handleAuthTokens handles Keystone v3 authentication
func handleAuthTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	// Validate authentication method
	if len(req.Auth.Identity.Methods) == 0 || req.Auth.Identity.Methods[0] != "password" {
		http.Error(w, "only password authentication is supported", http.StatusBadRequest)
		return
	}

	username := strings.TrimSpace(req.Auth.Identity.Password.User.Name)
	password := req.Auth.Identity.Password.User.Password
	domainName := req.Auth.Identity.Password.User.Domain.Name
	if domainName == "" {
		domainName = "default"
	}

	// Validate credentials
	s.mu.RLock()
	user, exists := s.users[username]
	s.mu.RUnlock()

	if !exists || user.Password != password || user.DomainID != domainName {
		http.Error(w, errInvalidCredentials.Error(), http.StatusUnauthorized)
		return
	}

	// Determine project
	projectName := req.Auth.Scope.Project.Name
	if projectName == "" {
		projectName = user.ProjectName
	}

	// Create token
	now := time.Now().UTC()
	tokenID := "token-" + randomID()

	// Determine role based on user
	var roleName string
	if user.Role != "" {
		roleName = user.Role
	} else {
		// Default to member if role not set
		roleName = "member"
	}

	// Create role based on user's role
	roleID := "role-" + roleName
	role := Role{
		ID:   roleID,
		Name: roleName,
	}

	t := Token{
		ID: tokenID,
		User: User{
			ID:       user.ID,
			Name:     user.Name,
			DomainID: user.DomainID,
		},
		Project: Project{
			ID:       user.ProjectID,
			Name:     projectName,
			DomainID: user.DomainID,
		},
		Roles:     []Role{role},
		ExpiresAt: now.Add(24 * time.Hour),
	}

	// Store token
	s.mu.Lock()
	s.tokens[tokenID] = t
	s.mu.Unlock()

	// In real OpenStack this is returned in the X-Subject-Token header
	w.Header().Set("X-Subject-Token", tokenID)
	w.Header().Set("Content-Type", "application/json")

	resp := AuthResponse{
		Token: t,
	}

	writeJSON(w, http.StatusCreated, resp)
}

// validateToken checks if a token is valid and not expired
func validateToken(tokenID string) (*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	token, exists := s.tokens[tokenID]
	if !exists {
		return nil, errTokenNotFound
	}

	if time.Now().UTC().After(token.ExpiresAt) {
		return nil, errTokenExpired
	}

	return &token, nil
}

// requireAuth middleware validates token before allowing access
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get token from X-Auth-Token header (OpenStack standard)
		tokenID := r.Header.Get("X-Auth-Token")
		if tokenID == "" {
			// Also check X-Subject-Token (alternative)
			tokenID = r.Header.Get("X-Subject-Token")
		}

		if tokenID == "" {
			http.Error(w, "missing authentication token", http.StatusUnauthorized)
			return
		}

		token, err := validateToken(tokenID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Store token in request context for handlers to use if needed
		// For now, we just validate it exists and is valid
		_ = token

		next(w, r)
	}
}

// handleFlavors handles both GET (list) and POST (create) for flavors
func handleFlavors(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleFlavorsList(w, r)
	case http.MethodPost:
		handleFlavorsCreate(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleFlavorsList(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	flavors := make([]Flavor, 0, len(s.flavors))
	for _, f := range s.flavors {
		flavors = append(flavors, f)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"flavors": flavors,
	})
}

func handleFlavorsCreate(w http.ResponseWriter, r *http.Request) {
	var req createFlavorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(req.Flavor.Name)
	if name == "" {
		http.Error(w, "flavor name is required", http.StatusBadRequest)
		return
	}
	if req.Flavor.VCPUs <= 0 {
		http.Error(w, "vcpus must be greater than 0", http.StatusBadRequest)
		return
	}
	if req.Flavor.RAM <= 0 {
		http.Error(w, "ram must be greater than 0", http.StatusBadRequest)
		return
	}
	if req.Flavor.Disk < 0 {
		http.Error(w, "disk must be non-negative", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if flavor name already exists
	for _, f := range s.flavors {
		if f.Name == name {
			http.Error(w, "flavor with this name already exists", http.StatusConflict)
			return
		}
	}

	id := "flavor-" + randomID()
	flavor := Flavor{
		ID:    id,
		Name:  name,
		VCPUs: req.Flavor.VCPUs,
		RAM:   req.Flavor.RAM,
		Disk:  req.Flavor.Disk,
	}

	s.flavors[id] = flavor

	writeJSON(w, http.StatusCreated, map[string]any{
		"flavor": flavor,
	})
}

func handleFlavorsDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	flavors := make([]Flavor, 0, len(s.flavors))
	for _, f := range s.flavors {
		flavors = append(flavors, f)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"flavors": flavors,
	})
}

func handleImagesList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	images := make([]Image, 0, len(s.images))
	for _, img := range s.images {
		images = append(images, img)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"images": images,
	})
}

func handleVolumesList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	volumes := make([]Volume, 0, len(s.volumes))
	for _, v := range s.volumes {
		volumes = append(volumes, v)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"volumes": volumes,
	})
}

func handleFloatingIPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	ips := make([]FloatingIP, 0, len(s.floatingIPs))
	for _, ip := range s.floatingIPs {
		ips = append(ips, ip)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"floatingips": ips,
	})
}

func handleKeypairs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		kps := make([]Keypair, 0, len(s.keypairs))
		for _, kp := range s.keypairs {
			kps = append(kps, kp)
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"keypairs": kps,
		})
	case http.MethodPost:
		var body struct {
			Keypair struct {
				Name      string `json:"name"`
				PublicKey string `json:"public_key"`
			} `json:"keypair"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		name := strings.TrimSpace(body.Keypair.Name)
		pub := strings.TrimSpace(body.Keypair.PublicKey)
		if name == "" || pub == "" {
			http.Error(w, "name and public_key are required", http.StatusBadRequest)
			return
		}

		s.mu.Lock()
		if _, exists := s.keypairs[name]; exists {
			s.mu.Unlock()
			http.Error(w, "keypair already exists", http.StatusConflict)
			return
		}
		kp := Keypair{
			Name:        name,
			PublicKey:   pub,
			Fingerprint: fakeFingerprint(pub),
			UserID:      "user-1",
		}
		s.keypairs[name] = kp
		s.mu.Unlock()

		writeJSON(w, http.StatusCreated, map[string]any{
			"keypair": kp,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleNetworks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	nets := make([]Network, 0, len(s.networks))
	for _, n := range s.networks {
		nets = append(nets, n)
	}
	s.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"networks": nets,
	})
}

// handleServersRoot dispatches to server list or create.
func handleServersRoot(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleServersList(w, r)
	case http.MethodPost:
		handleServersCreate(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleServersList(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	servers := make([]Server, 0, len(s.servers))
	for _, srv := range s.servers {
		servers = append(servers, srv)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"servers": servers,
	})
}

func handleServersCreate(w http.ResponseWriter, r *http.Request) {
	var req createServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(req.Server.Name)
	if name == "" || req.Server.ImageRef == "" || req.Server.FlavorRef == "" {
		http.Error(w, "missing required fields", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate flavor and image IDs (best-effort)
	if _, ok := s.flavors[req.Server.FlavorRef]; !ok {
		http.Error(w, "unknown flavorRef", http.StatusBadRequest)
		return
	}
	if _, ok := s.images[req.Server.ImageRef]; !ok {
		http.Error(w, "unknown imageRef", http.StatusBadRequest)
		return
	}

	id := "srv-" + randomID()
	now := time.Now().UTC()

	server := Server{
		ID:         id,
		Name:       name,
		Status:     "ACTIVE",
		PowerState: "ON",
		Flavor: FlavorRef{
			ID: req.Server.FlavorRef,
		},
		Image: ImageRef{
			ID: req.Server.ImageRef,
		},
		Volumes:    []VolumeAttachment{},
		FloatingIP: nil,
		CreatedAt:  now,
	}

	s.servers[id] = server

	writeJSON(w, http.StatusAccepted, map[string]any{
		"server": server,
	})
}

// handleServerByID manages GET and DELETE on /v2.1/servers/{id}
func handleServerByID(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/v2.1/servers/") {
		http.NotFound(w, r)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/v2.1/servers/")
	path = strings.Trim(path, "/")
	if path == "" {
		http.NotFound(w, r)
		return
	}

	segments := strings.Split(path, "/")
	id := segments[0]
	if id == "" {
		http.NotFound(w, r)
		return
	}

	if len(segments) > 1 && segments[1] == "action" {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleServerAction(w, r, id)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		server, ok := s.servers[id]
		s.mu.RUnlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"server": server,
		})
	case http.MethodDelete:
		s.mu.Lock()
		server, ok := s.servers[id]
		if ok {
			// release volumes
			for _, att := range server.Volumes {
				if vol, vok := s.volumes[att.VolumeID]; vok {
					vol.AttachedTo = ""
					vol.Status = "available"
					s.volumes[att.VolumeID] = vol
				}
			}
			// release floating IP
			if server.FloatingIP != nil {
				if ip, iok := s.floatingIPs[server.FloatingIP.ID]; iok {
					ip.ServerID = ""
					s.floatingIPs[ip.ID] = ip
				}
			}
			delete(s.servers, id)
		}
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleServerAction(w http.ResponseWriter, r *http.Request, serverID string) {
	var payload map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if len(payload) != 1 {
		http.Error(w, "provide exactly one action", http.StatusBadRequest)
		return
	}

	for action, raw := range payload {
		switch action {
		case "os-start":
			if err := changeServerStatus(serverID, "ACTIVE", "ON"); err != nil {
				writeActionError(w, err)
				return
			}
			writeServerResponse(w, serverID)
		case "os-stop":
			if err := changeServerStatus(serverID, "SHUTOFF", "OFF"); err != nil {
				writeActionError(w, err)
				return
			}
			writeServerResponse(w, serverID)
		case "reboot":
			if err := changeServerStatus(serverID, "REBOOTING", "ON"); err != nil {
				writeActionError(w, err)
				return
			}
			writeServerResponse(w, serverID)
		case "attach_volume":
			var req struct {
				VolumeID string `json:"volumeId"`
			}
			if err := json.Unmarshal(raw, &req); err != nil {
				http.Error(w, "invalid attach_volume payload", http.StatusBadRequest)
				return
			}
			if req.VolumeID == "" {
				http.Error(w, "volumeId required", http.StatusBadRequest)
				return
			}
			if err := attachVolume(serverID, req.VolumeID); err != nil {
				writeActionError(w, err)
				return
			}
			writeServerResponse(w, serverID)
		case "detach_volume":
			var req struct {
				VolumeID string `json:"volumeId"`
			}
			if err := json.Unmarshal(raw, &req); err != nil {
				http.Error(w, "invalid detach_volume payload", http.StatusBadRequest)
				return
			}
			if req.VolumeID == "" {
				http.Error(w, "volumeId required", http.StatusBadRequest)
				return
			}
			if err := detachVolume(serverID, req.VolumeID); err != nil {
				writeActionError(w, err)
				return
			}
			writeServerResponse(w, serverID)
		case "associate_floating_ip":
			var req struct {
				FloatingIPID string `json:"floatingIpId"`
			}
			if err := json.Unmarshal(raw, &req); err != nil {
				http.Error(w, "invalid associate_floating_ip payload", http.StatusBadRequest)
				return
			}
			if req.FloatingIPID == "" {
				http.Error(w, "floatingIpId required", http.StatusBadRequest)
				return
			}
			if err := associateFloatingIP(serverID, req.FloatingIPID); err != nil {
				writeActionError(w, err)
				return
			}
			writeServerResponse(w, serverID)
		case "disassociate_floating_ip":
			var req struct {
				FloatingIPID string `json:"floatingIpId"`
			}
			if err := json.Unmarshal(raw, &req); err != nil {
				http.Error(w, "invalid disassociate_floating_ip payload", http.StatusBadRequest)
				return
			}
			if req.FloatingIPID == "" {
				http.Error(w, "floatingIpId required", http.StatusBadRequest)
				return
			}
			if err := disassociateFloatingIP(serverID, req.FloatingIPID); err != nil {
				writeActionError(w, err)
				return
			}
			writeServerResponse(w, serverID)
		default:
			http.Error(w, "unsupported action "+action, http.StatusBadRequest)
		}
		return
	}
}

// --- Helpers ---

func changeServerStatus(serverID, status, power string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	server, ok := s.servers[serverID]
	if !ok {
		return errServerNotFound
	}
	server.Status = status
	server.PowerState = power
	s.servers[serverID] = server
	return nil
}

func attachVolume(serverID, volumeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	server, ok := s.servers[serverID]
	if !ok {
		return errServerNotFound
	}
	vol, ok := s.volumes[volumeID]
	if !ok {
		return errVolumeNotFound
	}
	if vol.AttachedTo != "" {
		return errVolumeAlreadyAttached
	}

	device := fmt.Sprintf("/dev/vd%c", 'b'+len(server.Volumes))
	attachment := VolumeAttachment{
		ID:       "att-" + randomID(),
		VolumeID: vol.ID,
		Device:   device,
	}

	server.Volumes = append(server.Volumes, attachment)
	vol.AttachedTo = server.ID
	vol.Status = "in-use"
	s.volumes[volumeID] = vol
	s.servers[serverID] = server
	return nil
}

func detachVolume(serverID, volumeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	server, ok := s.servers[serverID]
	if !ok {
		return errServerNotFound
	}
	if _, ok := s.volumes[volumeID]; !ok {
		return errVolumeNotFound
	}

	idx := -1
	for i, att := range server.Volumes {
		if att.VolumeID == volumeID {
			idx = i
			break
		}
	}
	if idx == -1 {
		return errVolumeNotAttached
	}

	server.Volumes = append(server.Volumes[:idx], server.Volumes[idx+1:]...)

	vol := s.volumes[volumeID]
	vol.AttachedTo = ""
	vol.Status = "available"
	s.volumes[volumeID] = vol
	s.servers[serverID] = server
	return nil
}

func associateFloatingIP(serverID, floatingID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	server, ok := s.servers[serverID]
	if !ok {
		return errServerNotFound
	}
	if server.FloatingIP != nil {
		return errFloatingIPInUse
	}

	ip, ok := s.floatingIPs[floatingID]
	if !ok {
		return errFloatingIPNotFound
	}
	if ip.ServerID != "" {
		return errFloatingIPInUse
	}

	ip.ServerID = server.ID
	s.floatingIPs[floatingID] = ip
	server.FloatingIP = &FloatingIPRef{ID: ip.ID, Address: ip.Address}
	s.servers[serverID] = server
	return nil
}

func disassociateFloatingIP(serverID, floatingID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	server, ok := s.servers[serverID]
	if !ok {
		return errServerNotFound
	}
	if server.FloatingIP == nil || server.FloatingIP.ID != floatingID {
		return errFloatingIPNotAssociated
	}

	ip, ok := s.floatingIPs[floatingID]
	if !ok {
		return errFloatingIPNotFound
	}

	ip.ServerID = ""
	server.FloatingIP = nil
	s.floatingIPs[floatingID] = ip
	s.servers[serverID] = server
	return nil
}

func writeServerResponse(w http.ResponseWriter, serverID string) {
	s.mu.RLock()
	server, ok := s.servers[serverID]
	s.mu.RUnlock()
	if !ok {
		http.Error(w, errServerNotFound.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"server": server,
	})
}

func writeActionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errServerNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, errVolumeNotFound),
		errors.Is(err, errVolumeAlreadyAttached),
		errors.Is(err, errVolumeNotAttached),
		errors.Is(err, errFloatingIPNotFound),
		errors.Is(err, errFloatingIPInUse),
		errors.Is(err, errFloatingIPNotAssociated):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func fakeFingerprint(pub string) string {
	// deterministic but simple fake fingerprint
	const letters = "0123456789abcdef"
	b := make([]byte, 32)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	// format as aa:bb:...
	var sb strings.Builder
	for i, c := range b {
		sb.WriteByte(c)
		if i%2 == 1 && i != len(b)-1 {
			sb.WriteByte(':')
		}
	}
	return sb.String()
}

func randomID() string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
