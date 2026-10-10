package webmanager

import _ "embed"

//go:embed static/index.html
var indexHTML string

//go:embed static/icon.svg
var iconSVG []byte
