// Go port of the modpot CORE check: decode a Modbus/TCP frame (hex) and
// classify it into a severity. Single binary, zero dependencies.
//
// Usage:
//
//	echo 000100000006010600010001 | modpot-go      # classify one hex frame
//	modpot-go 000100000006010300000001             # classify an arg
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

var functionNames = map[byte]string{
	0x01: "read_coils", 0x02: "read_discrete_inputs",
	0x03: "read_holding_registers", 0x04: "read_input_registers",
	0x05: "write_single_coil", 0x06: "write_single_register",
	0x0F: "write_multiple_coils", 0x10: "write_multiple_registers",
	0x16: "mask_write_register", 0x17: "read_write_multiple_registers",
	0x2B: "encapsulated_interface_transport", 0x08: "diagnostics",
	0x11: "report_server_id",
}

func contains(set []byte, b byte) bool {
	for _, x := range set {
		if x == b {
			return true
		}
	}
	return false
}

var readCodes = []byte{0x01, 0x02, 0x03, 0x04}
var writeCodes = []byte{0x05, 0x06, 0x0F, 0x10, 0x16}
var suspiciousCodes = []byte{0x08, 0x11, 0x2B, 0x16}

// Event is the decoded + classified result for one frame.
type Event struct {
	FunctionCode byte     `json:"function_code"`
	FunctionName string   `json:"function_name"`
	Category     string   `json:"category"`
	Severity     string   `json:"severity"`
	Address      int      `json:"address"`
	Quantity     int      `json:"quantity"`
	Reasons      []string `json:"reasons"`
}

// ParseAndClassify decodes one Modbus/TCP frame and classifies it.
func ParseAndClassify(buf []byte) (Event, error) {
	var e Event
	if len(buf) < 8 {
		return e, errors.New("frame too short")
	}
	pid := int(buf[2])<<8 | int(buf[3])
	if pid != 0 {
		return e, fmt.Errorf("bad protocol id 0x%04x", pid)
	}
	length := int(buf[4])<<8 | int(buf[5])
	if length < 2 {
		return e, fmt.Errorf("bad MBAP length %d", length)
	}
	fc := buf[7]
	e.FunctionCode = fc
	if name, ok := functionNames[fc]; ok {
		e.FunctionName = name
	} else {
		e.FunctionName = fmt.Sprintf("unknown_0x%02x", fc)
	}
	body := buf[8:]
	e.Address, e.Quantity = -1, -1
	if contains(readCodes, fc) && len(body) >= 4 {
		e.Address = int(body[0])<<8 | int(body[1])
		e.Quantity = int(body[2])<<8 | int(body[3])
	} else if (fc == 0x05 || fc == 0x06) && len(body) >= 4 {
		e.Address = int(body[0])<<8 | int(body[1])
	}
	classify(&e)
	return e, nil
}

func classify(e *Event) {
	fc := e.FunctionCode
	e.Reasons = []string{}
	switch {
	case contains(writeCodes, fc):
		e.Category = "write"
	case contains(readCodes, fc):
		e.Category = "read"
	default:
		if _, ok := functionNames[fc]; ok {
			e.Category = "control"
		} else {
			e.Category = "unknown"
		}
	}
	e.Severity = "info"
	if e.Category == "read" {
		e.Severity = "low"
		if e.Quantity > 125 {
			e.Severity = "medium"
			e.Reasons = append(e.Reasons, fmt.Sprintf("oversized read quantity %d (>125)", e.Quantity))
		}
	}
	if e.Category == "write" {
		e.Severity = "high"
		e.Reasons = append(e.Reasons, "register/coil write attempt against control device")
	}
	if contains(suspiciousCodes, fc) {
		e.Severity = "high"
		e.Reasons = append(e.Reasons, "suspicious function "+e.FunctionName+" (recon/tamper)")
	}
	if e.Category == "unknown" {
		e.Severity = "medium"
		e.Reasons = append(e.Reasons, "unknown function code (scanner/fuzzing)")
	}
	if len(e.Reasons) == 0 {
		e.Reasons = append(e.Reasons, "benign register read")
	}
}

func cleanHex(s string) string {
	var b strings.Builder
	for _, c := range s {
		if strings.ContainsRune("0123456789abcdefABCDEF", c) {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func main() {
	var input string
	if len(os.Args) > 1 {
		input = os.Args[1]
	} else {
		sc := bufio.NewScanner(os.Stdin)
		if sc.Scan() {
			input = sc.Text()
		}
	}
	raw, err := hex.DecodeString(cleanHex(input))
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad hex:", err)
		os.Exit(2)
	}
	e, err := ParseAndClassify(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse error:", err)
		os.Exit(2)
	}
	out, _ := json.MarshalIndent(map[string]any{"tool": "modpot", "event": e}, "", "  ")
	fmt.Println(string(out))
	if e.Severity == "high" {
		os.Exit(1)
	}
}
