package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server ServerConfig `yaml:"server"`
	Email  EmailConfig  `yaml:"email"`
	Auth   AuthConfig   `yaml:"auth"`
	TLS    TLSConfig    `yaml:"tls"`
}

type AuthConfig struct {
	Enabled        bool   `yaml:"enabled"`
	LDAPServer     string `yaml:"ldap_server"`
	LDAPPort       int    `yaml:"ldap_port"`
	UseTLS         bool   `yaml:"use_tls"`
	BaseDN         string `yaml:"base_dn"`
	BindUser       string `yaml:"bind_user"`
	BindPassword   string `yaml:"bind_password"`
	UserFilter     string `yaml:"user_filter"`
	SessionMinutes int    `yaml:"session_minutes"`
}

type TLSConfig struct {
	Enabled    bool   `yaml:"enabled"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	AutoGenDev bool   `yaml:"auto_generate_dev"`
}

type ServerConfig struct {
	Port int `yaml:"port"`
}

type EmailConfig struct {
	Enabled      bool     `yaml:"enabled"`
	IMAPServer   string   `yaml:"imap_server"`
	IMAPPort     int      `yaml:"imap_port"`
	SMTPServer   string   `yaml:"smtp_server"`
	SMTPPort     int      `yaml:"smtp_port"`
	Username     string   `yaml:"username"`
	Password     string   `yaml:"password"`
	FromAddr     string   `yaml:"from_addr"`
	ToAddr       []string `yaml:"to_addr"`
	PollInterval int      `yaml:"poll_interval_seconds"` // Seconds
}

// LoadConfig reads the configuration from the given path.
func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cfg := &Config{}
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
