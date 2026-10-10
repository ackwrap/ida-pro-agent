package webmanager

import "encoding/binary"

var iconSizes = [...]int{16, 24, 32, 48, 64, 128, 256}

var iconICO = buildIconICO()

func IconICO() []byte {
	return iconICO
}

func buildIconICO() []byte {
	images := make([][]byte, 0, len(iconSizes))
	for _, size := range iconSizes {
		images = append(images, buildIconBitmap(size))
	}
	directorySize := 6 + len(images)*16
	totalSize := directorySize
	for _, image := range images {
		totalSize += len(image)
	}
	icon := make([]byte, totalSize)
	binary.LittleEndian.PutUint16(icon[2:4], 1)
	binary.LittleEndian.PutUint16(icon[4:6], uint16(len(images)))
	offset := directorySize
	for index, image := range images {
		size := iconSizes[index]
		entry := icon[6+index*16 : 6+(index+1)*16]
		if size < 256 {
			entry[0] = byte(size)
			entry[1] = byte(size)
		}
		binary.LittleEndian.PutUint16(entry[4:6], 1)
		binary.LittleEndian.PutUint16(entry[6:8], 32)
		binary.LittleEndian.PutUint32(entry[8:12], uint32(len(image)))
		binary.LittleEndian.PutUint32(entry[12:16], uint32(offset))
		copy(icon[offset:], image)
		offset += len(image)
	}
	return icon
}

func buildIconBitmap(size int) []byte {
	pixelBytes := size * size * 4
	maskRowBytes := ((size + 31) / 32) * 4
	maskBytes := maskRowBytes * size
	bitmap := make([]byte, 40+pixelBytes+maskBytes)
	binary.LittleEndian.PutUint32(bitmap[0:4], 40)
	binary.LittleEndian.PutUint32(bitmap[4:8], uint32(size))
	binary.LittleEndian.PutUint32(bitmap[8:12], uint32(size*2))
	binary.LittleEndian.PutUint16(bitmap[12:14], 1)
	binary.LittleEndian.PutUint16(bitmap[14:16], 32)
	binary.LittleEndian.PutUint32(bitmap[20:24], uint32(pixelBytes))

	pixels := make([][4]byte, size*size)
	center := (size - 1) / 2
	radius := size/2 - 1
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx, dy := x-center, y-center
			if dx*dx+dy*dy <= radius*radius {
				pixels[y*size+x] = [4]byte{34, 25, 12, 255}
			}
		}
	}
	points := [][2]int{{size / 4, size * 9 / 32}, {size / 2, size * 18 / 32}, {size * 3 / 4, size * 9 / 32}}
	bottom := size * 23 / 32
	lineRadius := max(1, size/32)
	for _, segment := range [][4]int{
		{points[0][0], bottom, points[0][0], points[0][1]},
		{points[0][0], points[0][1], points[1][0], points[1][1]},
		{points[1][0], points[1][1], points[2][0], points[2][1]},
		{points[2][0], points[2][1], points[2][0], bottom},
	} {
		drawIconLine(pixels, size, segment[0], segment[1], segment[2], segment[3], lineRadius, [4]byte{32, 151, 255, 255})
	}
	for _, point := range points {
		drawIconDisc(pixels, size, point[0], point[1], max(1, size/16), [4]byte{235, 226, 65, 255})
	}

	pixelOffset := 40
	maskOffset := pixelOffset + pixelBytes
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			pixel := pixels[(size-1-y)*size+x]
			offset := pixelOffset + (y*size+x)*4
			copy(bitmap[offset:offset+4], pixel[:])
			if pixel[3] == 0 {
				bitmap[maskOffset+y*maskRowBytes+x/8] |= 1 << (7 - uint(x%8))
			}
		}
	}
	return bitmap
}

func drawIconLine(pixels [][4]byte, size, x0, y0, x1, y1, radius int, color [4]byte) {
	dx, sx := abs(x1-x0), 1
	if x0 > x1 {
		sx = -1
	}
	dy, sy := -abs(y1-y0), 1
	if y0 > y1 {
		sy = -1
	}
	err := dx + dy
	for {
		drawIconDisc(pixels, size, x0, y0, radius, color)
		if x0 == x1 && y0 == y1 {
			return
		}
		e2 := 2 * err
		if e2 >= dy {
			err += dy
			x0 += sx
		}
		if e2 <= dx {
			err += dx
			y0 += sy
		}
	}
}

func drawIconDisc(pixels [][4]byte, size, cx, cy, radius int, color [4]byte) {
	for y := cy - radius; y <= cy+radius; y++ {
		for x := cx - radius; x <= cx+radius; x++ {
			if x >= 0 && x < size && y >= 0 && y < size &&
				(x-cx)*(x-cx)+(y-cy)*(y-cy) <= radius*radius {
				pixels[y*size+x] = color
			}
		}
	}
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
