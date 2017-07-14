package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"os"
	"strings"
)

//PvfDirectory ..
// type PvfDirectory struct {
// 	//Tag Size
// 	Tag      []byte
// 	Revision uint32
// 	//aligned_index_header_size
// 	//index_header_crc
// 	//index_size
// 	data []byte
// }

//
//namesize
//name
//size
//crc
//offset
//

//PackEntity --
type PackEntity struct {
	key       uint32
	name      string
	crc       uint32
	offset    uint32
	size      uint32
	alignSize uint32
	content   []byte
}

var (
	gStringtable []string
	gEntities    []PackEntity
)

func decryptNcrc32(key uint32, b []byte) []byte {
	if len(b)%4 > 0 {
		return []byte{}
	}
	var result []byte
	result = make([]byte, len(b), len(b))
	e := binary.LittleEndian
	key ^= 0
	for i := 0; i+4 <= len(b); i += 4 {
		var x uint32
		x = e.Uint32(b[i:])
		x ^= 0x81A79011
		x ^= key
		x = (x >> 6) | (x << (32 - 6))
		e.PutUint32(result[i:], x)
	}
	return result
}

func getEntityContent(name string) []byte {
	for i := 0; i < len(gEntities); i++ {
		if name == gEntities[i].name {
			return gEntities[i].content
		}
	}
	return nil
}
func initStringtable(b []byte) {
	e := binary.LittleEndian
	count := e.Uint32(b)
	offsets := make([]uint32, count+1, count+1)
	gStringtable = make([]string, count, count)
	for i := 0; i < int(count+1); i++ {
		offsets[i] = e.Uint32(b[4+i*4:]) + 4
	}
	for i := 0; i < int(count); i++ {
		test := b[offsets[i]:offsets[i+1]]
		gStringtable[i] = string(test)
	}
}
func parserPvf(path string) []PackEntity {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	var lenstr uint32
	err = binary.Read(file, binary.LittleEndian, &lenstr)
	if err != nil {
		return nil
	}
	var tag []byte
	tag = make([]byte, lenstr)
	_, err = file.Read(tag)
	if err != nil {
		return nil
	}
	fmt.Println("tag:", string(tag))
	var revision uint32
	var alignedIndexHeaderSize uint32
	var indexHeaderCrc uint32
	var indexSize uint32
	err = binary.Read(file, binary.LittleEndian, &revision)
	if err != nil {
		return nil
	}
	fmt.Printf("revision:0x%08X\n", revision)
	err = binary.Read(file, binary.LittleEndian, &alignedIndexHeaderSize)
	if err != nil {
		return nil
	}
	fmt.Printf("alignedIndexHeaderSize:0x%08X\n", alignedIndexHeaderSize)
	err = binary.Read(file, binary.LittleEndian, &indexHeaderCrc)
	if err != nil {
		return nil
	}
	fmt.Printf("indexHeaderCrc:0x%08X\n", indexHeaderCrc)
	err = binary.Read(file, binary.LittleEndian, &indexSize)
	if err != nil {
		return nil
	}
	fmt.Printf("indexSize:0x%08X\n", indexSize)
	indexHeaderData := make([]byte, alignedIndexHeaderSize)

	_, err = file.Read(indexHeaderData)
	if err != nil {
		return nil
	}
	headerSize, _ := file.Seek(0, 1)
	fmt.Printf("0x%08X 0x%08X\n", headerSize, alignedIndexHeaderSize)
	indexHeaderData = decryptNcrc32(indexHeaderCrc, indexHeaderData)
	fmt.Println(hex.Dump(indexHeaderData[:0x100]))
	if crc32.Update(indexSize, crc32.IEEETable, indexHeaderData) != indexHeaderCrc {
		fmt.Println("CRC FAILD")
		return nil
	}
	reader := bytes.NewReader(indexHeaderData)

	entities := make([]PackEntity, indexSize)

	for i := 0; i < int(indexSize); i++ {
		var key uint32
		var namesize uint32
		var name string
		var size uint32
		var crc uint32
		var offset uint32
		var alignSize uint32

		err = binary.Read(reader, binary.LittleEndian, &key)
		if err != nil {
			return nil
		}
		err = binary.Read(reader, binary.LittleEndian, &namesize)
		if err != nil {
			return nil
		}
		bname := make([]byte, namesize)
		err = binary.Read(reader, binary.LittleEndian, &bname)
		if err != nil {
			return nil
		}
		name = string(bname)
		err = binary.Read(reader, binary.LittleEndian, &size)
		if err != nil {
			return nil
		}
		err = binary.Read(reader, binary.LittleEndian, &crc)
		if err != nil {
			return nil
		}
		err = binary.Read(reader, binary.LittleEndian, &offset)
		if err != nil {
			return nil
		}
		alignSize = (size + 3) & 0xFFFFFFFC
		entities[i].key = key
		entities[i].name = name
		entities[i].crc = crc
		entities[i].offset = offset
		entities[i].size = size
		entities[i].alignSize = alignSize

		var content []byte
		content = make([]byte, alignSize)
		file.Seek(int64(offset)+int64(headerSize), 0)
		file.Read(content)
		entities[i].content = decryptNcrc32(crc, content)
		if len(entities[i].content) > int(size) {
			entities[i].content = entities[i].content[:size]
		}
		content = []byte{}
	}

	return entities
}

func bar() {
	for i := 0; i < len(gEntities); i++ {
		fmt.Println(gEntities[i].name)
		buf := bytes.NewBuffer(gEntities[i].content)
		var mark uint16
		mark = 0
		if buf.Len() > 2 {
			err := binary.Read(buf, binary.LittleEndian, &mark)
			if err != nil {
				return
			}
		}
		// if strings.HasSuffix(gEntities[i].name, ".str") {
		// 	fmt.Println(string(gEntities[i].content))
		// 	file, err := os.Create("str.test")
		// 	if err != nil {
		// 		return
		// 	}
		// 	file.Write(gEntities[i].content)
		// 	file.Close()
		// } else {
		// 	continue
		// }
		if mark != 0xD0B0 {
			if !strings.HasSuffix(gEntities[i].name, ".ani") {
				fmt.Println(gEntities[i].name)
			}
		} else {

			for buf.Len() > 0 {
				var t byte
				var index int32
				err := binary.Read(buf, binary.LittleEndian, &t)
				if err != nil {
					break
				}
				if t == 4 {
					var num float32
					err = binary.Read(buf, binary.LittleEndian, &num)
					if err != nil {
						break
					}
					fmt.Println(num)
					continue
				}
				err = binary.Read(buf, binary.LittleEndian, &index)
				if err != nil {
					break
				}
				switch t {
				case 1, 2, 3, 9:
					fmt.Println(t, index)
				case 5, 6, 7, 8, 10:
					fmt.Println(t, gStringtable[index])
				default:
					fmt.Println("----BADTAG----", t, index)
				}
			}
		}
	}
}
func foo() {
	gEntities = parserPvf("./testdata/Script.pvf")
	initStringtable(getEntityContent("stringtable.bin"))
	fmt.Printf("count entity : %d\n", len(gEntities))
	bar()
}

// func main() {
// 	foo()
// }
