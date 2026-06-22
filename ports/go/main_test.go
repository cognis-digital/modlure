package main

import (
	"encoding/hex"
	"testing"
)

func decode(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func TestReadHoldingIsLow(t *testing.T) {
	e, err := ParseAndClassify(decode(t, "000100000006010300000001"))
	if err != nil {
		t.Fatal(err)
	}
	if e.FunctionName != "read_holding_registers" {
		t.Fatalf("got %s", e.FunctionName)
	}
	if e.Severity != "low" {
		t.Fatalf("want low, got %s", e.Severity)
	}
}

func TestWriteSingleIsHigh(t *testing.T) {
	e, err := ParseAndClassify(decode(t, "000200000006010600010001"))
	if err != nil {
		t.Fatal(err)
	}
	if e.Category != "write" || e.Severity != "high" {
		t.Fatalf("want write/high, got %s/%s", e.Category, e.Severity)
	}
}

func TestOversizedReadIsMedium(t *testing.T) {
	// qty 0x00C9 = 201 > 125
	e, _ := ParseAndClassify(decode(t, "0001000000060103000000C9"))
	if e.Severity != "medium" {
		t.Fatalf("want medium, got %s", e.Severity)
	}
}

func TestReportServerIdSuspicious(t *testing.T) {
	// MBAP tid=0009 pid=0000 len=0002 uid=01 + fc=0x11
	e, _ := ParseAndClassify(decode(t, "0009000000020111"))
	if e.Severity != "high" {
		t.Fatalf("want high for report_server_id, got %s", e.Severity)
	}
}

func TestBadProtocolIdErrors(t *testing.T) {
	_, err := ParseAndClassify(decode(t, "0001DEAD0006010300000001"))
	if err == nil {
		t.Fatal("expected error for bad protocol id")
	}
}

func TestShortFrameErrors(t *testing.T) {
	_, err := ParseAndClassify([]byte{0, 1, 0})
	if err == nil {
		t.Fatal("expected error for short frame")
	}
}

func TestUnknownFunctionIsMedium(t *testing.T) {
	// MBAP tid=0001 pid=0000 len=0002 uid=01 + fc=0x63 (unknown)
	e, _ := ParseAndClassify(decode(t, "0001000000020163"))
	if e.Category != "unknown" || e.Severity != "medium" {
		t.Fatalf("want unknown/medium, got %s/%s", e.Category, e.Severity)
	}
}

func TestCleanHexStrips(t *testing.T) {
	if cleanHex("00 01 ab") != "0001ab" {
		t.Fatalf("got %q", cleanHex("00 01 ab"))
	}
}
