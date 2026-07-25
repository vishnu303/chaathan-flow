package logger

import "io"

var FmtElapsed = fmtElapsed

func LogWrite(w io.Writer, s string) {
	logWrite(w, s)
}

func GetCurrentStep() int {
	scanUIMu.Lock()
	defer scanUIMu.Unlock()
	return currentStep
}
