package main

import mrand "math/rand/v2"

const skbMark = 0x43465721

type junkConfig struct {
	min   int
	max   int
	count int
}

func junkSize(jMin, jMax int) int {
	if jMax <= jMin {
		return jMin
	}
	return jMin + mrand.IntN(jMax-jMin+1)
}
