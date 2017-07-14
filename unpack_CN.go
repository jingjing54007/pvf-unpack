package main

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
	"unicode/utf16"
)

var cur string
var curcnt int

type PackHeadCN struct {
	magic           string     //00 "nkpi"
	unknown         [0x14]byte //04
	entityCount     uint32     //18
	unknown2        uint32     //1C
	dataSize        uint32     //20
	groupIndexCount uint32     //24
	hashSize        uint32     //28
	strSize         uint32     //2C
}

type RDAREntity struct {
	NameOffset  int32
	PathOffset  int32
	GroupIndex  uint32
	InnerOffset uint32
	Size        uint32
	Type        uint32 // 1: compiled file 3: .str .lua .xui plaintext
}

type RDARGroup struct {
	ChunkOffset uint32
	DecSize     uint32
}

type RDARScript struct {
	head     PackHeadCN
	entities []RDAREntity
	stringA  []byte
	stringW  []uint16
	group    []RDARGroup
	data     []byte
	mapdata  map[uint32][]byte
}

func (t *PackHeadCN) Parse(b []byte) error {
	if len(b) != 0x30 {
		return errors.New("bad len")
	}
	buf := bytes.NewBuffer(b)
	bm := make([]byte, 4)
	binary.Read(buf, binary.LittleEndian, &bm)
	t.magic = string(bm)
	binary.Read(buf, binary.LittleEndian, &t.unknown)
	binary.Read(buf, binary.LittleEndian, &t.entityCount)
	binary.Read(buf, binary.LittleEndian, &t.unknown2)
	binary.Read(buf, binary.LittleEndian, &t.dataSize)
	binary.Read(buf, binary.LittleEndian, &t.groupIndexCount)
	binary.Read(buf, binary.LittleEndian, &t.hashSize)
	binary.Read(buf, binary.LittleEndian, &t.strSize)
	return nil
}

func (t *PackHeadCN) String() string {
	var sb bytes.Buffer
	fmt.Fprintf(&sb, "PackHeadCN {")
	fmt.Fprintf(&sb, "magic: %v ", t.magic)
	fmt.Fprintf(&sb, "unknown: %v ", hex.EncodeToString(t.unknown[:]))
	fmt.Fprintf(&sb, "entityCount: %v ", t.entityCount)
	fmt.Fprintf(&sb, "unknown2: %v ", t.unknown2)
	fmt.Fprintf(&sb, "dataSize: %v ", t.dataSize)
	fmt.Fprintf(&sb, "groupIndexCount: %v ", t.groupIndexCount)
	fmt.Fprintf(&sb, "hashSize: %v ", t.hashSize)
	fmt.Fprintf(&sb, "strSize: %v", t.strSize)
	fmt.Fprintf(&sb, "}")
	return sb.String()
}

func pvfDecrypt(b []byte, key string) {
	if len(key) < 4 {
		return
	}
	e := binary.LittleEndian
	hash := 866031377*uint32(key[0]) + 915*(uint32(key[3])+915*(uint32(key[2])+915*uint32(key[1])))
	count := len(b) / 4
	remain := len(b) % 4

	for index := 0; index < count; index++ {
		h1 := 214013*hash + 2531011
		h2 := h1
		hash = 214013*h1 + 2531011
		e.PutUint32(b[index*4:], e.Uint32(b[index*4:])^((hash>>16)+(h2&0xFFFF0000)))
	}
	if remain > 0 {
		hash = ((214013*hash + 2531011) & 0xFFFF0000) + ((214013*(214013*hash+2531011) + 2531011) >> 16)
		for index := 0; index < remain; index++ {
			k := make([]byte, 4)
			e.PutUint32(k, hash)
			b[count*4+index] ^= k[index]
		}
	}
}

func pvfDecrypt2(b []byte, key string) {
	if len(key) < 4 {
		return
	}
	e := binary.LittleEndian
	hash := 866031377*uint32(key[0]) + 915*(uint32(key[3])+915*(uint32(key[2])+915*uint32(key[1])))
	count := len(b) / 4
	remain := len(b) % 4

	for index := 0; index < count; index++ {
		h1 := 214013*hash + 2531017
		h2 := h1
		hash = 214013*h1 + 2531017
		e.PutUint32(b[index*4:], e.Uint32(b[index*4:])^((hash>>16)+(h2&0xFFFF0000)))
	}
	if remain > 0 {
		hash = ((214013*hash + 2531017) & 0xFFFF0000) + ((214013*(214013*hash+2531017) + 2531017) >> 16)
		for index := 0; index < remain; index++ {
			k := make([]byte, 4)
			e.PutUint32(k, hash)
			b[count*4+index] ^= k[index]
		}
	}
}

func (t *RDARScript) GetStringByOffset(offset int32) string {
	var str = ""
	if offset < 0 {
		return str
	}
	nstart := offset / 2

	if (offset & 1) != 0 { //unicode
		for index := 0; index < len(t.stringW)-int(nstart); index++ {
			if t.stringW[int(nstart)+index] == 0 {
				str = string(utf16.Decode(t.stringW[nstart : int(nstart)+index]))
				break
			}
		}
	} else { //ansi
		for index := 0; index < len(t.stringA)-int(nstart); index++ {
			if t.stringA[int(nstart)+index] == 0 {
				str = string(t.stringA[nstart : int(nstart)+index])
				break
			}
		}
	}
	return str
}

func (t *RDARScript) GetGroupData(groupIndex uint32) []byte {
	if int(groupIndex) >= len(t.group) {
		return []byte{}
	}
	if _, ok := t.mapdata[groupIndex]; !ok {
		chunkOffset := uint32(0)
		if groupIndex != 0 {
			chunkOffset = t.group[groupIndex-1].ChunkOffset
		}
		chunkSize := t.group[groupIndex].ChunkOffset - chunkOffset
		body := make([]byte, chunkSize)
		copy(body, t.data[chunkOffset:chunkOffset+chunkSize])
		pvfDecrypt(body, "bODy")

		r, err := zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			return []byte{}
		}
		defer r.Close()
		chunk, _ := ioutil.ReadAll(r)
		t.mapdata[groupIndex] = chunk
	}
	return t.mapdata[groupIndex]
}

func (t *RDARScript) BuildHashStream(b []byte) error {
	if len(b) < 4 {
		return errors.New("fucking small buf @BuildHashStream")
	}
	buf := bytes.NewBuffer(b)
	var hcount uint32
	err := binary.Read(buf, binary.LittleEndian, &hcount)
	if err != nil {
		return err
	}
	hsize := 8 * hcount
	if hsize == 0 || buf.Len()-4 < int(hsize) {
		return errors.New("fucking small buf @BuildHashStream")
	}
	bh := make([]byte, hsize)
	err = binary.Read(buf, binary.LittleEndian, &bh)
	if err != nil {
		return err
	}

	return nil
}

func (t *RDARScript) BuildStringStream(b []byte) error {
	v6 := uint32(0)
	v7 := uint32(0)

	buf := bytes.NewBuffer(b)
	binary.Read(buf, binary.LittleEndian, &v6)
	binary.Read(buf, binary.LittleEndian, &v7)
	log.Println((v6 ^ 0x9A82F037) + (v7 ^ 0xAA74472E))

	binary.Read(buf, binary.LittleEndian, &v6)
	binary.Read(buf, binary.LittleEndian, &v7)

	compSize := v6 ^ 0xAA74472E
	decSize := compSize ^ v7
	ba := make([]byte, compSize)
	buf.Read(ba)
	pvfDecrypt2(ba, "StRa")
	r, err := zlib.NewReader(bytes.NewReader(ba))
	if err != nil {
		return err
	}
	defer r.Close()
	t.stringA, err = ioutil.ReadAll(r)
	if err != nil {
		return err
	}
	if len(t.stringA) != int(decSize) {
		log.Println("bad decompress size:", len(t.stringA), decSize)
	}
	binary.Read(buf, binary.LittleEndian, &v6)
	binary.Read(buf, binary.LittleEndian, &v7)

	compSize = v6 ^ 0x9A82F037
	decSize = compSize ^ v7

	bw := make([]byte, compSize)
	buf.Read(bw)
	pvfDecrypt2(bw, "StRw")
	r, err = zlib.NewReader(bytes.NewReader(bw))
	if err != nil {
		return err
	}
	defer r.Close()
	bsw, _ := ioutil.ReadAll(r)
	if len(bsw) != int(decSize) {
		log.Println("bad decompress size:", len(bsw), decSize)
	}
	t.stringW = make([]uint16, len(bsw)/2)
	err = binary.Read(bytes.NewBuffer(bsw), binary.LittleEndian, &t.stringW)
	if err != nil {
		return err
	}
	return nil
}

func (t *RDARScript) DecompileScript(b []byte) string {
	var sb bytes.Buffer
	buf := bytes.NewBuffer(b)
	for buf.Len() > 0 {
		Type, err := buf.ReadByte()
		if err != nil {
			return sb.String()
		}
		switch Type {
		case 0, 1: //int
			num := int32(0)
			err = binary.Read(buf, binary.LittleEndian, &num)
			if err != nil {
				return sb.String()
			}
			sb.WriteString(fmt.Sprintf("%v %v\n", Type, num))
		case 2: //float
			fnum := float32(0)
			err = binary.Read(buf, binary.LittleEndian, &fnum)
			if err != nil {
				return sb.String()
			}
			sb.WriteString(fmt.Sprintf("%v %v\n", Type, fnum))
		case 3, 5, 6: //3 [TAG] 5 6 ref string
			stroff := int32(0)
			err = binary.Read(buf, binary.LittleEndian, &stroff)
			if err != nil {
				return sb.String()
			}
			str := t.GetStringByOffset(stroff)
			sb.WriteString(fmt.Sprintf("%v %v\n", Type, str))
		case 7: //uint32
			num := uint32(0)
			err = binary.Read(buf, binary.LittleEndian, &num)
			if err != nil {
				return sb.String()
			}
			sb.WriteString(fmt.Sprintf("%v %v\n", Type, num))
		default:
			log.Println("\n" + sb.String() + "\n")
			log.Println("Unknown Data Type: ", Type, "\n"+hex.Dump(buf.Bytes()))
		}
	}
	return sb.String()
}

func (t *RDARScript) ParsePVF(filename string) error {
	t.mapdata = map[uint32][]byte{}
	file, err := os.Open(filename)
	if err != nil {
		return nil
	}
	defer file.Close()
	b := make([]byte, 0x30)
	err = binary.Read(file, binary.LittleEndian, &b)
	if err != nil {
		return err
	}
	pvfDecrypt(b, "hEAd")
	err = t.head.Parse(b)
	if err != nil {
		return err
	}
	log.Println(t.head.String())
	t.entities = make([]RDAREntity, t.head.entityCount)
	err = binary.Read(file, binary.LittleEndian, &t.entities)
	if err != nil {
		return err
	}

	b = make([]byte, t.head.hashSize)
	err = binary.Read(file, binary.LittleEndian, &b)
	if err != nil {
		return err
	}
	pvfDecrypt(b, "hash")
	t.BuildHashStream(b)

	b = make([]byte, t.head.strSize)
	err = binary.Read(file, binary.LittleEndian, &b)
	if err != nil {
		return err
	}
	err = t.BuildStringStream(b)
	if err != nil {
		return err
	}

	b = make([]byte, 8*t.head.groupIndexCount)
	err = binary.Read(file, binary.LittleEndian, &b)
	if err != nil {
		return err
	}
	pvfDecrypt(b, "grpi")
	t.group = make([]RDARGroup, t.head.groupIndexCount)
	err = binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &t.group)
	if err != nil {
		return err
	}
	t.data = make([]byte, t.head.dataSize)
	err = binary.Read(file, binary.LittleEndian, &t.data)
	if err != nil {
		return err
	}
	return err
}

func (t *RDARScript) TestFile(filename string) {
	for _, v := range t.entities {
		_ = t.GetStringByOffset(v.PathOffset)
		name := t.GetStringByOffset(v.NameOffset)
		if v.Type == 1 {
			if strings.HasSuffix(name, filename) {
				groupData := t.GetGroupData(v.GroupIndex)
				b := groupData[v.InnerOffset : v.InnerOffset+v.Size]
				t.DecompileScript(b)
			}
		} else if v.Type == 3 {
		} else {
			log.Println("Bad File Type:", v.Type)
		}
	}
}

func (t *RDARScript) Extra(root string) {
	go func() {
		total := len(t.entities)
		for {
			log.Println(curcnt, "/", total, cur)
			time.Sleep(time.Second)
			if curcnt+1 >= total {
				break
			}
		}
	}()
	for index, v := range t.entities {
		path := t.GetStringByOffset(v.PathOffset)
		name := t.GetStringByOffset(v.NameOffset)
		var content []byte
		cur = fmt.Sprintf("%s/%s\n", path, name)
		curcnt = index
		groupData := t.GetGroupData(v.GroupIndex)
		b := groupData[v.InnerOffset : v.InnerOffset+v.Size]
		if v.Type == 1 {
			content = []byte(t.DecompileScript(b))
		} else if v.Type == 3 {
			content = b
		} else {
			log.Println("Bad File Type:", v.Type)
		}

		err := os.MkdirAll(root+path, 0755)
		if err != nil {
			log.Println()
			continue
		}

		f, err := os.Create(root + path + "/" + name)
		if err != nil {
			log.Println()
			continue
		}
		f.Write(content)
		f.Close()
	}
}

func (t *RDARScript) Build(srcroot string, objroot string, filename string) {
}

func (t *RDARScript) Rebuild(srcroot string, objroot string, filename string) {
}

func fooCN() {
	var script RDARScript

	err := script.ParsePVF("./testdata/Script_CN.pvf")
	if err != nil {
		return
	}
	script.TestFile("monstername.lst")
	//script.Extra("F:/pvf_extra_170620/")
}

func main() {
	fooCN()
}
