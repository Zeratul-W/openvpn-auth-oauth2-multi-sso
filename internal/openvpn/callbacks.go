package openvpn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
)

// AcceptClient accepts an OpenVPN client connection.
// It reads the client configuration from the CCD path if enabled.
// claims parameter contains OAuth2 ID token claims that will be written to JSON file if enabled.
func (c *Client) AcceptClient(ctx context.Context, logger *slog.Logger, client state.ClientIdentifier, reAuth bool, username, clientConfigName string, claims map[string]any) {
	if reAuth {
		logger.LogAttrs(ctx, slog.LevelInfo, "client re-authentication")

		if _, err := c.SendCommandf(ctx, `client-auth-nt %d %d`, client.CID, client.KID); err != nil {
			logger.LogAttrs(ctx, slog.LevelWarn, "failed to accept client",
				slog.Any("error", err),
			)
		}

		return
	}

	c.acceptClientAuth(ctx, logger, client, username, clientConfigName, claims)
}

//nolint:cyclop
func (c *Client) acceptClientAuth(ctx context.Context, logger *slog.Logger, client state.ClientIdentifier, username, clientConfigName string, claims map[string]any) {
	var (
		err           error
		tokenUsername string
	)

	logger.LogAttrs(ctx, slog.LevelInfo, "client authentication")

	clientConfig, err := c.readClientConfig(clientConfigName)
	switch {
	case err != nil:
		logger.LogAttrs(ctx, slog.LevelDebug, "failed to read client config",
			slog.String("config", clientConfigName),
			slog.Any("error", err),
		)
	case len(clientConfig) > 0:
		logger.LogAttrs(ctx, slog.LevelDebug, "applying client config from CCD",
			slog.String("config", clientConfigName),
			slog.Any("content", clientConfig),
		)
	default:
		logger.LogAttrs(ctx, slog.LevelInfo, "no client config found in CCD",
			slog.String("config", clientConfigName),
		)
	}

	if c.conf.OpenVPN.AuthTokenUser && client.UsernameIsDefined == 0 {
		tokenUsername = base64.StdEncoding.EncodeToString([]byte(username))
		if tokenUsername == "" {
			tokenUsername = "dXNlcm5hbWUK" // "username" //nolint:gosec // No hardcoded credentials
			username = "username"
		}
	}

	if c.conf.OpenVPN.OverrideUsername && username != "" {
		clientConfig = append(clientConfig, fmt.Sprintf(`override-username "%s"`, username))
	} else if tokenUsername != "" {
		clientConfig = append(clientConfig, fmt.Sprintf(`push "auth-token-user %s"`, tokenUsername))
	}

	// Write OAuth2 claims to JSON file for server-side scripts
	if c.conf.OpenVPN.ClaimsFile.Enabled && claims != nil {
		if err := c.writeClaimsFile(ctx, logger, client, username, claims); err != nil {
			logger.LogAttrs(ctx, slog.LevelWarn, "failed to write claims file",
				slog.Any("error", err),
			)
		}
	}

	// Store claims for later use in ESTABLISHED event (for ipset management)
	if c.conf.OpenVPN.IPSet.Enabled && claims != nil {
		c.claimsMu.Lock()
		c.clientClaims[client.CommonName] = claims
		c.claimsMu.Unlock()
	}

	if len(clientConfig) == 0 {
		_, err = c.SendCommandf(ctx, `client-auth-nt %d %d`, client.CID, client.KID)
	} else {
		sb := strings.Builder{}

		sb.WriteString(fmt.Sprintf("client-auth %d %d\r\n", client.CID, client.KID))

		for _, line := range clientConfig {
			sb.WriteString(strings.TrimSpace(line))
			sb.WriteString("\r\n")
		}

		sb.WriteString("END")

		_, err = c.SendCommand(ctx, sb.String(), false)
	}

	if err != nil {
		logger.LogAttrs(ctx, slog.LevelWarn, "failed to accept client",
			slog.Any("error", err),
		)
	}
}

func (c *Client) DenyClient(ctx context.Context, logger *slog.Logger, client state.ClientIdentifier, reason string) {
	logger.LogAttrs(ctx, slog.LevelInfo, fmt.Sprintf("deny OpenVPN client cid %d, kid %d", client.CID, client.KID))

	_, err := c.SendCommandf(ctx, `client-deny %d %d "%s"`, client.CID, client.KID, reason)
	if err != nil {
		logger.LogAttrs(ctx, slog.LevelWarn, "failed to deny client",
			slog.Any("error", err),
		)
	}
}

func (c *Client) readClientConfig(username string) ([]string, error) {
	if !c.conf.OpenVPN.ClientConfig.Enabled || c.conf.OpenVPN.ClientConfig.Path.IsEmpty() || len(username) == 0 {
		return make([]string, 0), nil
	}

	clientConfigFile, err := c.conf.OpenVPN.ClientConfig.Path.Open(username + ".conf")
	if err != nil {
		return make([]string, 0), fmt.Errorf("failed to open client config file: %w", err)
	}

	clientConfigBytes, err := io.ReadAll(clientConfigFile)
	if err != nil {
		return make([]string, 0), fmt.Errorf("failed to read client config file: %w", err)
	}

	return strings.Split(strings.TrimSpace(strings.ReplaceAll(string(clientConfigBytes), "\r", "")), "\n"), nil
}

// ClaimsFileData represents the structure of the claims JSON file
type ClaimsFileData struct {
	Timestamp   string         `json:"timestamp"`
	CommonName  string         `json:"common_name"`
	Username    string         `json:"username"`
	CID         uint64         `json:"cid"`
	KID         uint64         `json:"kid"`
	SessionID   string         `json:"session_id,omitempty"`
	Claims      map[string]any `json:"claims"`
}

// writeClaimsFile writes OAuth2 claims to a JSON file for server-side scripts to use
func (c *Client) writeClaimsFile(ctx context.Context, logger *slog.Logger, client state.ClientIdentifier, username string, claims map[string]any) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(c.conf.OpenVPN.ClaimsFile.Path, 0755); err != nil {
		return fmt.Errorf("failed to create claims directory: %w", err)
	}

	// Use common_name as filename (sanitize it for filesystem)
	sanitizedName := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' || r == '@' {
			return r
		}
		return '_'
	}, client.CommonName)

	if sanitizedName == "" {
		sanitizedName = fmt.Sprintf("client_%d_%d", client.CID, client.KID)
	}

	filename := filepath.Join(c.conf.OpenVPN.ClaimsFile.Path, sanitizedName+".json")

	// Prepare claims data
	claimsData := ClaimsFileData{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		CommonName: client.CommonName,
		Username:   username,
		CID:        client.CID,
		KID:        client.KID,
		SessionID:  client.SessionID,
		Claims:     claims,
	}

	// Marshal to JSON with indentation for readability
	jsonData, err := json.MarshalIndent(claimsData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal claims to JSON: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filename, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write claims file: %w", err)
	}

	logger.LogAttrs(ctx, slog.LevelInfo, "wrote claims to file",
		slog.String("file", filename),
		slog.String("common_name", client.CommonName),
	)

	return nil
}

// deleteClaimsFile removes the claims JSON file when client disconnects
func (c *Client) deleteClaimsFile(ctx context.Context, logger *slog.Logger, commonName string) {
	// Sanitize common_name same way as in writeClaimsFile
	sanitizedName := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' || r == '@' {
			return r
		}
		return '_'
	}, commonName)

	if sanitizedName == "" {
		logger.LogAttrs(ctx, slog.LevelWarn, "cannot delete claims file: empty common name")
		return
	}

	filename := filepath.Join(c.conf.OpenVPN.ClaimsFile.Path, sanitizedName+".json")

	if err := os.Remove(filename); err != nil {
		if !os.IsNotExist(err) {
			logger.LogAttrs(ctx, slog.LevelWarn, "failed to delete claims file",
				slog.String("file", filename),
				slog.Any("error", err),
			)
		}
	} else {
		logger.LogAttrs(ctx, slog.LevelInfo, "deleted claims file",
			slog.String("file", filename),
			slog.String("common_name", commonName),
		)
	}
}
