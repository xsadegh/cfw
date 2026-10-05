//go:build !darwin

package main

import "syscall"

func egressInterface() (int, string) {
	return 0, ""
}

func bindEgress(_ syscall.RawConn, _ int) error {
	return nil
}
