package main

import (
	"os/exec"
)

func findExecutable(name string) (string, error) {
	return exec.LookPath(name)
}

func createCommand(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}
