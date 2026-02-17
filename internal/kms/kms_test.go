package kms

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestMockProvider_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	p := NewMockProvider(key)
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand: %v", err)
	}

	wrapped, err := p.WrapDEK(dek, MockKeyID)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if len(wrapped) == 0 {
		t.Fatal("wrapped is empty")
	}

	unwrapped, err := p.UnwrapDEK(wrapped, MockKeyID)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if !bytes.Equal(unwrapped, dek) {
		t.Error("unwrapped DEK does not match original")
	}
}

func TestMockProvider_WrongKeyID(t *testing.T) {
	p := NewMockProvider(make([]byte, 32))
	dek := make([]byte, 32)
	wrapped, err := p.WrapDEK(dek, MockKeyID)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	_, err = p.UnwrapDEK(wrapped, "wrong-id")
	if err == nil {
		t.Error("expected error for wrong key ID")
	}
}

func TestRegistry_GetMock(t *testing.T) {
	p := Get("mock")
	if p == nil {
		t.Fatal("Get(\"mock\") returned nil")
	}
	dek := []byte("32-bytes-dek-for-testing-roundtrip!!")
	wrapped, err := p.WrapDEK(dek, MockKeyID)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	unwrapped, err := p.UnwrapDEK(wrapped, MockKeyID)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if !bytes.Equal(unwrapped, dek) {
		t.Error("round-trip via registry mock failed")
	}
}

func TestProviders_ContainsMockAndAWS(t *testing.T) {
	names := Providers()
	hasMock := false
	hasAWS := false
	for _, n := range names {
		if n == "mock" {
			hasMock = true
		}
		if n == "aws" {
			hasAWS = true
		}
	}
	if !hasMock {
		t.Error("Providers() should contain \"mock\"")
	}
	if !hasAWS {
		t.Error("Providers() should contain \"aws\"")
	}
}
