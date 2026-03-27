package openvpn

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"gopkg.in/yaml.v3"
)

// IPSetManager manages ipset rules based on OAuth2 claims
type IPSetManager struct {
	conf   *config.Config
	logger *slog.Logger
}

// IPSetConfig represents the external YAML configuration for ipset rules
type IPSetConfig struct {
	Rules []config.OpenVPNIPSetRule `yaml:"rules"`
}

// NewIPSetManager creates a new IPSet manager
func NewIPSetManager(conf *config.Config, logger *slog.Logger) (*IPSetManager, error) {
	if !conf.OpenVPN.IPSet.Enabled {
		return &IPSetManager{conf: conf, logger: logger}, nil
	}

	// Load rules from external YAML file if config path is set
	if conf.OpenVPN.IPSet.ConfigPath != "" {
		if err := loadIPSetRules(conf); err != nil {
			return nil, fmt.Errorf("failed to load ipset rules: %w", err)
		}
	}

	logger.LogAttrs(context.Background(), slog.LevelInfo, "ipset manager initialized",
		slog.Int("rules_count", len(conf.OpenVPN.IPSet.Rules)),
	)

	return &IPSetManager{conf: conf, logger: logger}, nil
}

// loadIPSetRules loads ipset rules from external YAML file
func loadIPSetRules(conf *config.Config) error {
	data, err := os.ReadFile(conf.OpenVPN.IPSet.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read ipset config file: %w", err)
	}

	var ipsetConfig IPSetConfig
	if err := yaml.Unmarshal(data, &ipsetConfig); err != nil {
		return fmt.Errorf("failed to parse ipset config YAML: %w", err)
	}

	// Merge rules from file with any rules in main config
	conf.OpenVPN.IPSet.Rules = append(conf.OpenVPN.IPSet.Rules, ipsetConfig.Rules...)

	return nil
}

// AddClientToIPSet adds a client IP to appropriate ipset based on claims
func (m *IPSetManager) AddClientToIPSet(ctx context.Context, client state.ClientIdentifier, vpnIP string, claims map[string]any) error {
	if !m.conf.OpenVPN.IPSet.Enabled || claims == nil {
		return nil
	}

	// Get the claim field value (e.g., email)
	claimValue, ok := claims[m.conf.OpenVPN.IPSet.ClaimField]
	if !ok {
		m.logger.LogAttrs(ctx, slog.LevelWarn, "claim field not found in token",
			slog.String("claim_field", m.conf.OpenVPN.IPSet.ClaimField),
		)
		return nil
	}

	claimStr, ok := claimValue.(string)
	if !ok {
		m.logger.LogAttrs(ctx, slog.LevelWarn, "claim field is not a string",
			slog.String("claim_field", m.conf.OpenVPN.IPSet.ClaimField),
		)
		return nil
	}

	// Get groups if available
	var groups []string
	if groupsClaim, ok := claims["groups"]; ok {
		switch v := groupsClaim.(type) {
		case []string:
			groups = v
		case []interface{}:
			for _, item := range v {
				if str, ok := item.(string); ok {
					groups = append(groups, str)
				}
			}
		}
	}

	// Get cognito groups if available
	var cognitoGroups []string
	if cognitoGroupsClaim, ok := claims["cognito:groups"]; ok {
		switch v := cognitoGroupsClaim.(type) {
		case []string:
			cognitoGroups = v
		case []interface{}:
			for _, item := range v {
				if str, ok := item.(string); ok {
					cognitoGroups = append(cognitoGroups, str)
				}
			}
		}
	}

	// Map group IDs to group names if mapping is configured
	if len(m.conf.OpenVPN.IPSet.GroupIDMap) > 0 {
		mappedGroups := make([]string, 0, len(groups))
		for _, groupID := range groups {
			if groupName, ok := m.conf.OpenVPN.IPSet.GroupIDMap[groupID]; ok {
				mappedGroups = append(mappedGroups, groupName)
				m.logger.LogAttrs(ctx, slog.LevelDebug, "mapped group ID to name",
					slog.String("group_id", groupID),
					slog.String("group_name", groupName),
				)
			} else {
				// Keep original ID if no mapping found
				mappedGroups = append(mappedGroups, groupID)
			}
		}
		groups = mappedGroups
	}

	// Match rules and add to ipset
	for _, rule := range m.conf.OpenVPN.IPSet.Rules {
		if m.matchesRule(rule, claimStr, groups, cognitoGroups, claims) {
			if err := m.addToIPSet(ctx, rule.SetName, vpnIP); err != nil {
				m.logger.LogAttrs(ctx, slog.LevelError, "failed to add to ipset",
					slog.String("set_name", rule.SetName),
					slog.String("ip", vpnIP),
					slog.Any("error", err),
				)
				continue
			}

			m.logger.LogAttrs(ctx, slog.LevelInfo, "added client to ipset",
				slog.String("rule_name", rule.Name),
				slog.String("set_name", rule.SetName),
				slog.String("ip", vpnIP),
				slog.String("claim_value", claimStr),
			)
		}
	}

	return nil
}

// RemoveClientFromIPSet removes a client IP from all ipsets
func (m *IPSetManager) RemoveClientFromIPSet(ctx context.Context, vpnIP string) error {
	if !m.conf.OpenVPN.IPSet.Enabled {
		return nil
	}

	// Remove from all configured ipsets
	for _, rule := range m.conf.OpenVPN.IPSet.Rules {
		if err := m.removeFromIPSet(ctx, rule.SetName, vpnIP); err != nil {
			m.logger.LogAttrs(ctx, slog.LevelWarn, "failed to remove from ipset",
				slog.String("set_name", rule.SetName),
				slog.String("ip", vpnIP),
				slog.Any("error", err),
			)
			continue
		}

		m.logger.LogAttrs(ctx, slog.LevelDebug, "removed client from ipset",
			slog.String("set_name", rule.SetName),
			slog.String("ip", vpnIP),
		)
	}

	return nil
}

// matchesRule checks if the claim value matches the rule criteria
func (m *IPSetManager) matchesRule(rule config.OpenVPNIPSetRule, claimValue string, groups []string, cognitoGroups []string, claims map[string]any) bool {
	// Check email match
	if len(rule.MatchEmails) > 0 {
		matched := false
		for _, email := range rule.MatchEmails {
			if email == claimValue || strings.HasSuffix(claimValue, "@"+strings.TrimPrefix(email, "*@")) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check groups match
	if len(rule.MatchGroups) > 0 {
		matched := false
		for _, ruleGroup := range rule.MatchGroups {
			for _, userGroup := range groups {
				if ruleGroup == userGroup {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check cognito groups match
	if len(rule.MatchCognitoGroups) > 0 {
		matched := false
		for _, ruleGroup := range rule.MatchCognitoGroups {
			for _, userGroup := range cognitoGroups {
				if ruleGroup == userGroup {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check custom claims match
	if len(rule.MatchClaims) > 0 {
		for key, expectedValue := range rule.MatchClaims {
			claimVal, ok := claims[key]
			if !ok {
				return false
			}
			claimStr := fmt.Sprintf("%v", claimVal)
			if claimStr != expectedValue {
				return false
			}
		}
	}

	return true
}

// addToIPSet adds an IP to an ipset
func (m *IPSetManager) addToIPSet(ctx context.Context, setName, ip string) error {
	cmd := exec.CommandContext(ctx, "ipset", "add", setName, ip, "-exist")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset add failed: %w, output: %s", err, string(output))
	}
	return nil
}

// removeFromIPSet removes an IP from an ipset
func (m *IPSetManager) removeFromIPSet(ctx context.Context, setName, ip string) error {
	cmd := exec.CommandContext(ctx, "ipset", "del", setName, ip, "-exist")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset del failed: %w, output: %s", err, string(output))
	}
	return nil
}

