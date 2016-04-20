from struct import pack, unpack

def ParseAll(msfile):
    data = open(msfile, "r+").read()
    offset = 0
    magic, = unpack("<H", data[offset:offset+2])
    print "Offset: 0x%08X\tMagic number: 0x%02X" % (offset, magic)
    offset += 2

    unknown, = unpack("<B", data[offset:offset+1])
    print "Offset: 0x%08X\tUnkown byte: 0x%01X" % (offset, unknown)
    offset += 1

    flag, = unpack("<I", data[offset:offset+4])
    print "Offset: 0x%08X\tUnkown flag: 0x%08X" % (offset, flag),
    print "(looks like GPIO port output speed)"
    offset += 4

    print "Offset: 0x%08X\tZero padding" % offset
    offset += 8

    sections, = unpack("<I", data[offset:offset+4])
    print "Offset: 0x%08X\tTotal number of sections: 0x%08X" % (offset, sections)
    offset += 4
    
    fwsize, = unpack("<I", data[offset:offset+4])
    print "Offset: 0x%08X\tFirmware size: 0x%08X" % (offset, fwsize)
    offset += 4

    maincrc, = unpack("<I", data[offset:offset+4])
    print "Offset: 0x%08X\tCRC of whole firmware: 0x%08X" % (offset, maincrc)
    offset += 4

    print "Section table:"
    for i in range(sections):
        section = data[offset:offset+10]
        type, secoffset, secsize = unpack("<HII", section)
        print "Offset 0x%08X\tsection type 0x%04X:" % (offset, type)
        print "\tSection offset 0x%08X, size 0x%08X [ends at 0x%08X]" %\
            (secoffset, secsize, secoffset+secsize)

        if type == 0xC002:
            print "\t*** Section has different header format ***"
            offset += 10
            continue

        section_data = data[secoffset:secoffset+secsize]
        vnum1, vnum2 = unpack("<II", section_data[4:4+8])
        num1, num2, num3 = unpack("<HHI", section_data[4:4+8])
        size2, _, checksum = unpack("<III", section_data[0x10:0x10+12])
        print "\tOffset: 0x%08X\tVersion number: 0x%08X.0x%08X" % (4, vnum1, vnum2),
        print "(shown as %d.%d.%d)" % (num2, num1, num3)
        print "\tOffset: 0x%08X\tSection size: 0x%08X" % (0x10, size2)
        print "\tOffset: 0x%08X\tSection CRC: 0x%08X" % (0x18, checksum)

        # with open("section-%04X.bin" % type, "w+") as f:
        #     f.write(section_data)
        offset += 10
                        
ParseAll("FirmwareUpdate.bin")
