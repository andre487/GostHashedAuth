package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"
)

const iterations = 600000
const maxFile = 1 << 20
const maxBody = 32 << 10

var version = "dev"

type credential struct {
	salt []byte
	key  []byte
}

func validUsername(value string) bool {
	return value != "" && len(value) <= 1024 && !strings.ContainsFunc(value, unicode.IsControl)
}

func decode(r io.Reader, limit int64, value any) error {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(data)) > limit {
		return errors.New("Input exceeds size limit or cannot be read")
	}
	// Unmarshal rejects trailing JSON documents; never include decoder errors containing input.
	if json.Unmarshal(data, value) != nil {
		return errors.New("Invalid JSON")
	}
	return nil
}

func parseHash(value string) (credential, error) {
	parts := strings.Split(value, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "pbkdf2-sha256" || parts[2] != fmt.Sprint(iterations) {
		return credential{}, errors.New("Unsupported password hash")
	}
	salt, saltErr := hex.DecodeString(parts[3])
	key, keyErr := hex.DecodeString(parts[4])
	if saltErr != nil || keyErr != nil || len(salt) != 16 || len(key) != 32 {
		return credential{}, errors.New("Invalid password hash")
	}
	return credential{salt, key}, nil
}

func hashPassword(password string) (string, error) {
	if password == "" || len(password) > 4096 {
		return "", errors.New("Password must contain 1 to 4096 bytes")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", errors.New("Cannot generate salt")
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		return "", errors.New("Cannot derive password hash")
	}
	return fmt.Sprintf("$pbkdf2-sha256$%d$%x$%x", iterations, salt, key), nil
}

func loadUsers(r io.Reader) (map[string]credential, error) {
	var hashes map[string]string
	if err := decode(r, maxFile, &hashes); err != nil {
		return nil, err
	}
	if len(hashes) == 0 {
		return nil, errors.New("Users file must not be empty")
	}
	users := make(map[string]credential, len(hashes))
	for user, hash := range hashes {
		if !validUsername(user) {
			return nil, errors.New("Invalid username in users file")
		}
		c, err := parseHash(hash)
		if err != nil {
			return nil, err
		}
		users[user] = c
	}
	return users, nil
}

func authHandler(users map[string]credential) http.Handler {
	// ponytail: bounded queue and two KDF workers; tune after measuring real proxy load.
	pending := make(chan struct{}, 32)
	slots := make(chan struct{}, 2)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path != "/auth" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var request struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		if decode(r.Body, maxBody, &request) != nil || !validUsername(request.Username) || len(request.Password) == 0 || len(request.Password) > 4096 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		select {
		case pending <- struct{}{}:
			defer func() { <-pending }()
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		case <-r.Context().Done():
			return
		case <-timer.C:
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		c, exists := users[request.Username]
		if !exists {
			// Unknown accounts pay the same KDF cost as known accounts.
			c = credential{make([]byte, 16), make([]byte, 32)}
		}
		key, err := pbkdf2.Key(sha256.New, request.Password, c.salt, iterations, 32)
		ok := err == nil && subtle.ConstantTimeCompare(key, c.key) == 1 && exists
		response := struct {
			OK bool   `json:"ok"`
			ID string `json:"id,omitempty"`
		}{OK: ok}
		if ok {
			response.ID = request.Username
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	})
}

func loopbackAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	return err == nil && port != "" && ip != nil && ip.IsLoopback()
}

func run(args []string, input io.Reader, output io.Writer) error {
	if len(args) > 0 && args[0] == "hash" {
		if len(args) != 1 {
			return errors.New("Usage: gost-hashed-auth hash < plaintext-users.json > users.json")
		}
		var passwords map[string]string
		if err := decode(input, maxFile, &passwords); err != nil {
			return err
		}
		if len(passwords) == 0 {
			return errors.New("Users input must not be empty")
		}
		hashes := make(map[string]string, len(passwords))
		for user, password := range passwords {
			if !validUsername(user) {
				return errors.New("Invalid username")
			}
			hash, err := hashPassword(password)
			if err != nil {
				return err
			}
			hashes[user] = hash
		}
		return json.NewEncoder(output).Encode(hashes)
	}
	flags := flag.NewFlagSet("gost-hashed-auth", flag.ContinueOnError)
	address := flags.String("listen", "127.0.0.1:18083", "Loopback HTTP listen address")
	usersPath := flags.String("users", "/etc/gost-hashed-auth/users.json", "JSON username-to-hash map; restart to reload")
	check := flags.Bool("check", false, "Validate the users file and exit")
	showVersion := flags.Bool("version", false, "Print version and exit")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("Unexpected positional arguments")
	}
	if *showVersion {
		_, err := fmt.Fprintln(output, version)
		return err
	}
	file, err := os.Open(*usersPath)
	if err != nil {
		return errors.New("Cannot open users file")
	}
	users, err := loadUsers(file)
	_ = file.Close()
	if err != nil || *check {
		return err
	}
	if !loopbackAddress(*address) {
		return errors.New("Listen address must use a numeric loopback IP")
	}
	server := &http.Server{Addr: *address, Handler: authHandler(users), ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second,
		MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	log.Printf("GostHashedAuth %s listening on %s", version, *address)
	return server.ListenAndServe()
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
