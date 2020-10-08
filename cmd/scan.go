/*
Copyright © 2020 Aaron Tatum <aarontatum13@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	errs "github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// MySQLInfo contains metadata about a scanned mysql instance
type MySQLInfo struct {
	AuthPluginName    string
	CharacterSet      string
	HandshakeProtocol int
	ServerVersion     string
	StatusFlag        string

	connectionID    string
	authPluginData  string
	capabilityFlags []byte
}

type options struct {
	Host    string
	Port    string
	Timeout time.Duration
}

var (
	errNoHost          = errors.New("missing input value host (--host)")
	errNoPort          = errors.New("missing input value port (--port)")
	errZeroTimeout     = errors.New("timeout must be a non-zero number")
	errToManyConn      = errors.New("too many connections")
	errEarlyEOF        = errors.New("received EOF before receiving all promised data")
	errUnknownProtocol = errors.New("unknown protocol version expecting version 9 or 10")
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:     "scan",
	Aliases: []string{"s"},
	Short:   "Scan/Detect MySQL running on a port",
	Long:    "Scan and detect MySQL running on a part on a given host. Return some information about the MySQL instance configuration",
	Run: func(cmd *cobra.Command, args []string) {
		opts, err := parseFlags(cmd)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Starting scan...\n\n")
		result, err := Scan(opts.Host, opts.Port, opts.Timeout)
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() {
				log.Fatalf("Warning! connection timeout on read, instance at: %s:%s is most likely not a MySQL instance or the timeout period was too short to complete the handshake\n", opts.Host, opts.Port)
			}
			log.Fatal(err)
		}

		if err := table(result); err != nil {
			log.Fatalf("Error outputting table format: %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().String("port", "", "Port to scan")
	scanCmd.Flags().String("host", "", "Host to scan")
	scanCmd.Flags().IntP("timeout", "t", 500, "Timeout for dial and connection reads in milliseconds")
}

// Scan scans the specified host and port testing if the port is open and if its running mysql
func Scan(host string, port string, timeout time.Duration) (*MySQLInfo, error) {
	target := fmt.Sprintf("%s:%s", host, port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			return nil, errToManyConn
		}

		return nil, errs.Wrap(err, "port: "+port+" is closed")
	}
	fmt.Printf("Port: %s is open\n\n", port)

	if err = conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	lenBuf := make([]byte, 4)
	_, err = conn.Read(lenBuf)
	if err != nil {
		return nil, err
	}

	lenData, err := msgLength(lenBuf)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, lenData)
	_, err = conn.Read(buf)
	if err == io.EOF {
		return nil, errEarlyEOF
	}
	if err != nil {
		return nil, err
	}

	result, err := parseHandshake(buf)
	if err != nil {
		return nil, err
	}

	if err := conn.Close(); err != nil {
		return nil, err
	}

	return result, nil
}

func getServerVersion(b []byte, i int) (string, int) {
	var version []byte
	for _, v := range b[i:] {
		if v != 0 {
			version = append(version, v)
		} else {
			i++
			break
		}
		i++
	}

	return string(version), i
}

func getConnectionID(b []byte, i int) (string, int) {
	return string(b[i : i+4]), i + 4
}

func msgLength(b []byte) (int32, error) {
	buf := bytes.NewReader(b)
	var result int32
	err := binary.Read(buf, binary.LittleEndian, &result)

	return result, err
}

func parseFlags(cmd *cobra.Command) (*options, error) {
	host, err := cmd.Flags().GetString("host")
	if err != nil {
		return nil, err
	}
	if host == "" {
		return nil, errNoHost
	}
	port, err := cmd.Flags().GetString("port")
	if err != nil {
		return nil, err
	}
	if port == "" {
		return nil, errNoPort
	}
	if port != "3306" {
		fmt.Printf("Warning! Port: %s is not typically used by MySQL\n\n", port)
	}
	timeout, err := cmd.Flags().GetInt("timeout")
	if err != nil {
		return nil, err
	}
	if timeout == 0 {
		return nil, errZeroTimeout
	}

	f := &options{
		Host:    host,
		Port:    port,
		Timeout: time.Duration(timeout) * time.Millisecond,
	}

	return f, nil
}

// Notes For Handshake Parsing:
// Field (Length of Bytes in message)
// Protocol Version (1)
// Server Version (Null Terminated String)
// Connection_ID (4)
// Auth_Plugin_Data_Part_1 (8)
// Filler (1)
// Capability_Flag_1 (2)
// Character_Set (1)
// StatusFlags (2)
// Capability_Flags_2 (2)
// Auth_Plugin_Data_Len (1)
// Auth_Plugin_Name (Null Terminated String)
func parseHandshake(b []byte) (*MySQLInfo, error) {
	var info MySQLInfo
	if len(b) == 0 {
		return nil, errors.New("empty handshake")
	}

	i := 0

	info.HandshakeProtocol = int(b[i])

	switch info.HandshakeProtocol {
	case 10:
		result, err := parseV10(b, &info)
		if err != nil {
			return nil, err
		}

		return result, nil
	case 9:
		result, err := parseV9(b, &info)
		if err != nil {
			return nil, err
		}

		return result, nil
	default:
		return nil, errUnknownProtocol
	}
}

func parseV9(handshake []byte, info *MySQLInfo) (*MySQLInfo, error) {
	i := 1
	v, i := getServerVersion(handshake, i)
	info.ServerVersion = v

	cID, i := getConnectionID(handshake, i)
	info.connectionID = cID

	var pluginData []byte
	for _, v := range handshake[i:] {
		if v != 0 {
			pluginData = append(pluginData, v)
		} else {
			break
		}
	}

	info.authPluginData = string(pluginData)

	return info, nil
}

func parseV10(handshake []byte, info *MySQLInfo) (*MySQLInfo, error) {
	i := 1
	v, i := getServerVersion(handshake, i)
	info.ServerVersion = v

	cID, i := getConnectionID(handshake, i)
	info.connectionID = cID

	info.authPluginData = string(handshake[i : i+8])
	i += 9

	info.capabilityFlags = make([]byte, 4)
	info.capabilityFlags[2] = handshake[i]
	info.capabilityFlags[3] = handshake[i+1]
	i += 2

	info.CharacterSet = sqlCharSets[int(handshake[i])]
	i++

	statusFlag := make([]byte, 2)
	statusFlag[0] = handshake[i]
	statusFlag[1] = handshake[i+1]
	hexFlag := make([]byte, len(statusFlag)*2)
	_ = hex.Encode(hexFlag, statusFlag)
	info.StatusFlag = sqlStatusFlags[string(hexFlag)]
	i += 2

	info.capabilityFlags[0] = handshake[i]
	info.capabilityFlags[1] = handshake[i+1]
	i += 2

	i += 11 // length of auth plugin data is always 21 so its ok to skip the byte containing its length and the next 10 bytes that are reserved

	info.authPluginData += string(handshake[i : i+13])
	i += 13

	var pluginName []byte
	for _, v := range handshake[i:] {
		if v != 0 {
			pluginName = append(pluginName, v)
		} else {
			break
		}
	}

	info.AuthPluginName = string(pluginName)

	return info, nil
}

func table(info *MySQLInfo) error {
	tw := tabwriter.NewWriter(os.Stdout, 0, 8, 0, '\t', 0)
	fmt.Fprintln(tw, "MySQL Version\tHandshake Protocol\tAuth Plugin\tCharacter Set\tStatus Flag")
	fmt.Fprintln(tw, info.ServerVersion+"\t"+strconv.Itoa(info.HandshakeProtocol)+"\t"+info.AuthPluginName+"\t"+info.CharacterSet+"\t"+info.StatusFlag)

	return tw.Flush()
}
