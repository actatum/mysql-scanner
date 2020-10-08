package cmd

import (
	"strconv"
	"testing"
	"time"

	"github.com/orlangure/gnomock"
	"github.com/orlangure/gnomock/preset/mysql"
	"github.com/stretchr/testify/assert"
)

func TestScan(t *testing.T) {
	tt := []struct {
		name     string
		expected *MySQLInfo
		wantErr  bool
	}{
		{name: "integration test", expected: &MySQLInfo{
			ServerVersion:     "8.0.21",
			HandshakeProtocol: 10,
			AuthPluginName:    "caching_sha2_password",
			CharacterSet:      "utf8mb4_0900_ai_ci",
			StatusFlag:        "SERVER_STATUS_NO_BACKSLASH_ESCAPES",
		}, wantErr: false},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			m := mysql.Preset()
			c, err := gnomock.Start(m)
			if err != nil {
				t.Error(err)
			}
			defer gnomock.Stop(c)

			port := strconv.Itoa(c.Ports.Get("default").Port)

			got, err := Scan(c.Host, port, 500*time.Millisecond)

			if tc.wantErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)

				assert.Equal(t, tc.expected.ServerVersion, got.ServerVersion)
				assert.Equal(t, tc.expected.HandshakeProtocol, got.HandshakeProtocol)
				assert.Equal(t, tc.expected.AuthPluginName, got.AuthPluginName)
				assert.Equal(t, tc.expected.CharacterSet, got.CharacterSet)
				assert.Equal(t, tc.expected.StatusFlag, got.StatusFlag)
			}
		})
	}
}
