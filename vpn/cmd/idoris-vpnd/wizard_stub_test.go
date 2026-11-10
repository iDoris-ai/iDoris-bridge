package main

import "testing"

func TestJoinAndGatewayReturnNotImplemented(t *testing.T) {
	err := joinCmd(nil, deps{})
	if err == nil || err.Error() != "join: not implemented yet" {
		t.Fatalf("join: %v", err)
	}
	err = gatewayCmd(nil, deps{})
	if err == nil || err.Error() != "gateway: not implemented yet" {
		t.Fatalf("gateway: %v", err)
	}
}
