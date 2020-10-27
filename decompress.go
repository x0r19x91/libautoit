package libautoit

import "encoding/binary"

type IDecompressor interface {
	Decompress() ([]byte, error)
}

func CreateDecompressor(ver AutoItVersion, inpBuf []byte, decompSize uint32) IDecompressor {
	if ver == EA06 {
		return NewEa06Decompressor(inpBuf, decompSize)
	} else if ver == EA05 {
		return NewEa05Decompressor(inpBuf, decompSize)
	} else {
		return NewLegacyDecompressor(inpBuf, decompSize)
	}
}

type ea06Decomp struct {
	inputBuffer          []byte
	outputBuffer         []byte
	inPos, count, outPos int
	ans                  uint32
	compressedSize       uint32
	decompressedSize     int
}

type ea05Decomp struct {
	inputBuffer          []byte
	outputBuffer         []byte
	inPos, count, outPos int
	ans                  uint32
	compressedSize       uint32
	decompressedSize     int
}

type legacyDecomp struct {
	inputBuffer          []byte
	outputBuffer         []byte
	inPos, count, outPos int
	ans                  uint32
	decompressedSize     int
}

func NewLegacyDecompressor(inpBuf []byte, decompSize uint32) *legacyDecomp {
	return &legacyDecomp{
		inputBuffer:      inpBuf,
		outputBuffer:     make([]byte, decompSize),
		inPos:            0,
		count:            0,
		outPos:           0,
		ans:              0,
		decompressedSize: int(decompSize),
	}
}

func (r *legacyDecomp) extractBits(nbits int) (uint32, error) {
	r.ans &= 0xffff
	for nbits > 0 {
		nbits--
		if r.count == 0 {
			tmp, err := r.nextByte()
			if err != nil {
				return ^uint32(0), err
			}
			a := uint32(tmp)
			tmp, err = r.nextByte()
			if err != nil {
				return ^uint32(0), err
			}
			b := uint32(tmp)
			r.ans |= (a << 8) | b
			r.count = 16
		}
		r.ans <<= 1
		r.count--
	}
	return r.ans >> 0x10, nil
}

func (r *legacyDecomp) customExtractBits() (uint32, error) {
	var ans uint32
	n, err := r.extractBits(2)
	if err != nil {
		return ^uint32(0), err
	}
	if n == 3 {
		ans = 3
		n, err = r.extractBits(3)
		if err != nil {
			return ^uint32(0), err
		}
		if n == 7 {
			ans = 10
			n, err = r.extractBits(5)
			if err != nil {
				return ^uint32(0), err
			}
			if n == 0x1f {
				ans = 0x29
				for {
					n, err = r.extractBits(8)
					if err != nil {
						return ^uint32(0), err
					}
					if n != 0xff {
						break
					}
					ans += 0xff
				}
			}
		}
	}
	return ans + n + 3, nil
}

func (r *legacyDecomp) nextByte() (byte, error) {
	if r.inPos >= len(r.inputBuffer) {
		return 0xff, ErrOutOfBounds
	}
	r.inPos++
	return r.inputBuffer[r.inPos-1], nil
}

func (l *legacyDecomp) Decompress() ([]byte, error) {
	if IsPrintable(l.inputBuffer) {
		return l.inputBuffer, nil
	} else {
		// Weird ...
		// old autoit uses JB01 format but different decompressor
		// so, let's try to decompress with the old decompressor
		// if it fails, try the new JB01 decompressor
		tmpBuf := make([]byte, len(l.inputBuffer))
		copy(tmpBuf, l.inputBuffer)
		// legacy versions of autoit
		out, err := l.LegacyDecompress()
		if err != nil {
			// latest version of autoit
			jb0x := NewJB01Decompressor(tmpBuf, l.decompressedSize)
			return jb0x.Decompress()
		} else {
			return out, nil
		}
	}
}

func (l *legacyDecomp) LegacyDecompress() ([]byte, error) {
	_, err := l.extractBits(8)
	if err != nil {
		return nil, err
	}
	_, err = l.extractBits(8)
	if err != nil {
		return nil, err
	}
	_, err = l.extractBits(8)
	if err != nil {
		return nil, err
	}
	_, err = l.extractBits(8)
	if err != nil {
		return nil, err
	}
	tmp, err := l.extractBits(16)
	if err != nil {
		return nil, err
	}
	size := tmp << 16
	tmp, err = l.extractBits(16)
	if err != nil {
		return nil, err
	}
	size |= tmp

	for l.outPos < l.decompressedSize {
		choice, err := l.extractBits(1)
		if err != nil {
			return nil, err
		}
		if choice == 0 {
			tmp, err = l.extractBits(8)
			if err != nil {
				return nil, err
			}
			l.outputBuffer[l.outPos] = byte(tmp)
			l.outPos++
		} else {
			tmp, err = l.extractBits(13)
			if err != nil {
				return nil, err
			}
			delta := l.outPos - 3 - int(tmp)
			tmp, err = l.extractBits(4)
			if err != nil {
				return nil, err
			}
			count := 3 + int(tmp)
			if (l.outPos+count >= l.decompressedSize) || (delta < 0) ||
				(delta+count > l.decompressedSize) {
				return nil, ErrDecompressFailed
			}
			copyOverlapping(l.outputBuffer[l.outPos:l.outPos+count], l.outputBuffer[delta:delta+count])
			l.outPos += count
		}
	}

	return l.outputBuffer, nil
}

func NewEa05Decompressor(inpBuf []byte, decompSize uint32) *ea05Decomp {
	return &ea05Decomp{
		inputBuffer:  inpBuf,
		outputBuffer: make([]byte, decompSize),
		inPos:        0,
		ans:          0,
		count:        0,
		outPos:       0,
		//compressedSize:   r.CompressedSize,
		decompressedSize: int(decompSize),
	}
}

func NewEa06Decompressor(inpBuf []byte, decompSize uint32) *ea06Decomp {
	return &ea06Decomp{
		inputBuffer:  inpBuf,
		outputBuffer: make([]byte, decompSize),
		inPos:        0,
		ans:          0,
		count:        0,
		outPos:       0,
		//compressedSize:   r.CompressedSize,
		decompressedSize: int(decompSize),
	}
}

func (r *ea05Decomp) nextByte() byte {
	r.inPos++
	return r.inputBuffer[r.inPos-1]
}

func (r *ea06Decomp) nextByte() byte {
	r.inPos++
	return r.inputBuffer[r.inPos-1]
}

func (r *ea05Decomp) extractBits(nbits int) uint32 {
	r.ans &= 0xffff
	for nbits > 0 {
		nbits--
		if r.count == 0 {
			a := uint32(r.nextByte())
			b := uint32(r.nextByte())
			r.ans |= (a << 8) | b
			r.count = 16
		}
		r.ans <<= 1
		r.count--
	}
	return r.ans >> 0x10
}

func (r *ea05Decomp) customExtractBits() uint32 {
	var ans uint32
	n := r.extractBits(2)
	if n == 3 {
		ans = 3
		n = r.extractBits(3)
		if n == 7 {
			ans = 10
			n = r.extractBits(5)
			if n == 0x1f {
				ans = 0x29
				for {
					n = r.extractBits(8)
					if n != 0xff {
						break
					}
					ans += 0xff
				}
			}
		}
	}
	return ans + n + 3
}

func (r *ea06Decomp) extractBits(nbits int) uint32 {
	r.ans &= 0xffff
	for nbits > 0 {
		nbits--
		if r.count == 0 {
			a := uint32(r.nextByte())
			b := uint32(r.nextByte())
			r.ans |= (a << 8) | b
			r.count = 16
		}
		r.ans <<= 1
		r.count--
	}
	return r.ans >> 0x10
}

func (r *ea06Decomp) customExtractBits() uint32 {
	var ans uint32
	n := r.extractBits(2)
	if n == 3 {
		ans = 3
		n = r.extractBits(3)
		if n == 7 {
			ans = 10
			n = r.extractBits(5)
			if n == 0x1f {
				ans = 0x29
				for {
					n = r.extractBits(8)
					if n != 0xff {
						break
					}
					ans += 0xff
				}
			}
		}
	}
	return ans + n + 3
}

func (r *ea06Decomp) Decompress() ([]byte, error) {
	signature := string(r.inputBuffer[:4])
	size := int(binary.BigEndian.Uint32(r.inputBuffer[4:8]))
	if r.decompressedSize < size {
		r.outputBuffer = nil
		r.decompressedSize = size
		r.outputBuffer = make([]byte, size)
	}
	r.inPos = 8
	if signature != "EA06" {
		return nil, ErrInvalidSignature
	}

	for r.outPos < r.decompressedSize {
		bits := r.extractBits(1)
		if bits == 1 {
			r.outputBuffer[r.outPos] = byte(r.extractBits(8))
			r.outPos++
		} else {
			v := int(r.extractBits(0xf))
			t := int(r.customExtractBits())
			delta := r.outPos - v
			copyOverlapping(r.outputBuffer[r.outPos:r.outPos+t], r.outputBuffer[delta:delta+t])
			r.outPos += t
		}
	}

	return r.outputBuffer, nil
}

func (r *ea05Decomp) Decompress() ([]byte, error) {
	signature := string(r.inputBuffer[:4])
	size := int(binary.BigEndian.Uint32(r.inputBuffer[4:8]))
	if r.decompressedSize < size {
		r.outputBuffer = nil
		r.decompressedSize = size
		r.outputBuffer = make([]byte, size)
	}
	r.inPos = 8
	if signature != "EA05" {
		return nil, ErrInvalidSignature
	}
	for r.outPos < r.decompressedSize {
		bits := r.extractBits(1)
		if bits == 0 {
			r.outputBuffer[r.outPos] = byte(r.extractBits(8))
			r.outPos++
		} else {
			v := int(r.extractBits(0xf))
			t := int(r.customExtractBits())
			delta := r.outPos - v
			copyOverlapping(r.outputBuffer[r.outPos:r.outPos+t], r.outputBuffer[delta:delta+t])
			r.outPos += t
		}
	}

	return r.outputBuffer, nil
}
