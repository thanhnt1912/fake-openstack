package main

import "time"

type Token struct {
	ID        string    `json:"id"`
	User      User      `json:"user"`
	Project   Project   `json:"project"`
	ExpiresAt time.Time `json:"expires_at"`
}

type User struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	DomainID string `json:"domain_id"`
}

type Project struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	DomainID string `json:"domain_id"`
}

type Flavor struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	VCPUs int    `json:"vcpus"`
	RAM   int    `json:"ram_mb"`
	Disk  int    `json:"disk_gb"`
}

type Image struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	OSDiskSize  int    `json:"os_disk_gb"`
	OS          string `json:"os"`
	Description string `json:"description"`
}

type Server struct {
	ID         string             `json:"id"`
	Name       string             `json:"name"`
	Status     string             `json:"status"`
	PowerState string             `json:"power_state"`
	Flavor     FlavorRef          `json:"flavor"`
	Image      ImageRef           `json:"image"`
	Volumes    []VolumeAttachment `json:"attached_volumes"`
	FloatingIP *FloatingIPRef     `json:"floating_ip,omitempty"`
	CreatedAt  time.Time          `json:"created"`
}

type FlavorRef struct {
	ID string `json:"id"`
}

type ImageRef struct {
	ID string `json:"id"`
}

type createServerRequest struct {
	Server struct {
		Name      string `json:"name"`
		ImageRef  string `json:"imageRef"`
		FlavorRef string `json:"flavorRef"`
	} `json:"server"`
}

type createFlavorRequest struct {
	Flavor struct {
		Name  string `json:"name"`
		VCPUs int    `json:"vcpus"`
		RAM   int    `json:"ram"`
		Disk  int    `json:"disk"`
	} `json:"flavor"`
}

type Volume struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	SizeGB     int    `json:"size_gb"`
	Status     string `json:"status"`
	AttachedTo string `json:"attached_to,omitempty"`
}

type VolumeAttachment struct {
	ID       string `json:"id"`
	VolumeID string `json:"volume_id"`
	Device   string `json:"device"`
}

type FloatingIP struct {
	ID       string `json:"id"`
	Address  string `json:"address"`
	ServerID string `json:"server_id,omitempty"`
}

type FloatingIPRef struct {
	ID      string `json:"id"`
	Address string `json:"address"`
}

// Keypair represents an SSH keypair (Nova os-keypairs)
type Keypair struct {
	Name        string `json:"name"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	UserID      string `json:"user_id,omitempty"`
}

// Network represents a simple Neutron network
type Network struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	CIDR string `json:"cidr"`
}

// AuthRequest represents Keystone v3 authentication request
type AuthRequest struct {
	Auth struct {
		Identity struct {
			Methods  []string `json:"methods"`
			Password struct {
				User struct {
					Name   string `json:"name"`
					Domain struct {
						Name string `json:"name"`
					} `json:"domain"`
					Password string `json:"password"`
				} `json:"user"`
			} `json:"password"`
		} `json:"identity"`
		Scope struct {
			Project struct {
				Name   string `json:"name"`
				Domain struct {
					Name string `json:"name"`
				} `json:"domain"`
			} `json:"project"`
		} `json:"scope,omitempty"`
	} `json:"auth"`
}

// AuthResponse represents Keystone v3 authentication response
type AuthResponse struct {
	Token Token `json:"token"`
}

// StoredUser represents a user with credentials in the system
type StoredUser struct {
	ID          string
	Name        string
	Password    string
	DomainID    string
	ProjectID   string
	ProjectName string
}
