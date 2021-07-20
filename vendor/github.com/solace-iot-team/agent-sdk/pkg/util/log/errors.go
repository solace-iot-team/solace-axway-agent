package log

import configerrors "github.com/solace-iot-team/agent-sdk/pkg/util/errors"

// Log Config Errors
var (
	ErrInvalidLogConfig = configerrors.Newf(1410, "logging configuration error - %v does not meet criteria (%v)")
)
