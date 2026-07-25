package runnerfaketest

import (
	"context"
	"strings"

	"github.com/vishnu303/chaathan/pkg/runner"
)

// DummyRunner is a mock runner for testing.
type DummyRunner struct {
	StdoutMap map[string]string
	Default   string
	LastCmd   string
	LastArgs  []string
	LastOpts  []runner.Option
	ErrMap    map[string]error // inject error per command/arg substring
	Err       error            // inject global error if set
}

func (d *DummyRunner) Run(ctx context.Context, cmd string, args []string, opts ...runner.Option) (string, error) {
	d.LastCmd = cmd
	d.LastArgs = args
	d.LastOpts = opts

	if d.Err != nil {
		return "", d.Err
	}

	for k, err := range d.ErrMap {
		if strings.Contains(cmd, k) {
			return "", err
		}
		for _, arg := range args {
			if strings.Contains(arg, k) {
				return "", err
			}
		}
	}

	for k, v := range d.StdoutMap {
		if strings.Contains(cmd, k) {
			return v, nil
		}
		for _, arg := range args {
			if strings.Contains(arg, k) {
				return v, nil
			}
		}
	}
	return d.Default, nil
}

func (d *DummyRunner) GetOptions() *runner.RunOptions {
	opts := &runner.RunOptions{}
	for _, o := range d.LastOpts {
		o(opts)
	}
	return opts
}
