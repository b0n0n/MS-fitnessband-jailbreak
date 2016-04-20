from binascii import crc32
from struct import pack, unpack
import os
import re

def VersionNumPatch(data, orig_version):
        '''
        patch the orig_version number to a bigger one, make sure the orig_version
        number is the one on your fitness band!
        '''
        sections = unpack("<I", data[15:15+4])[0]
        ptr = 27
        
        print "[+]Patching version number..."
        for i in range(sections):
                section = data[ptr:ptr+10]
                type, offset, size = unpack("<HII", section)
                if type == 0xc002:
                        print "\tUnknown header type C002 ignored..."
                        ptr+=10
                        continue
                section_data = data[offset:offset+size]

                num1, num2, num3 = orig_version.split(".")
                new_version = (int(num1)<<16) + (int(num2)+1)
                section_data = section_data[:4] + pack("<I", new_version) + \
                               section_data[8:]
                data = data[:offset] + section_data + data[offset+size:]
                
                vnum1, vnum2 = unpack("<II", section_data[4:4+8])
                print "\tNew version number: %x.%x" % (vnum1, vnum2)

                ptr+=10
                
        return data
                          
def TextPad(string):
        '''
        pad system string
        '''
        padded = ""
        for i in string:
                padded += i+"\x00"
        return padded
        
def ChkMainCrc(filename):
        '''
        check main CRC
        '''
        data = open(filename,'rb').read()

        for i in range(0, len(data)-4):
	        # these 4 bytes are the CRC embedded in the FirmwareUpdate.bin
	        block = data[i:i+4]

	        # calculate CRC for the rest of the data (replace the 4 bytes with 0's)
	        c = (crc32(data[:i] + "\0"*4 + data[i+4:],0xFFFFFFFF)^0xFFFFFFFF) & 0xffffffff

	        if pack("<I", c) in block:
		        print "Found at offset dec=%d hex=%08X" % (i,i)
		        print "CRC=%08X" % c
		        break

def ChkSectCrc(filename):
        '''
        check section CRCs
        '''
        data = open(filename, 'rb').read()

        sections = unpack("<I", data[15:15+4])[0]
        print sections, "sections"

        ptr = 27

        for i in range(sections):
                section = data[ptr:ptr+10]
                print "%08X" % (ptr + 10)
                type, offset, size = unpack("<HII", section)
                print "0x%04X: at offset 0x%08X, size 0x%08X [ends at 0x%08X]" %\
                        (type, offset, size, offset+size)

                section_data = data[offset:offset+size]
                size2, _, checksum = unpack("<III", section_data[16:16+12])
                if size2 == size:
                        vnum1, vnum2, vnum3 = unpack("<HHH", section_data[4:4+6])
                        print "\tVersion number: %d.%d.%d" % (vnum1, vnum2, vnum3)
                        vnum1, vnum2 = unpack("<II", section_data[4:4+8])
                        print "\tVersion number: %d.%d" % (vnum1, vnum2)
                        

                        c = (crc32(section_data[:24] + "\0"*4 + section_data[28:], \
                                   0xFFFFFFFF)^0xFFFFFFFF) & 0xffffffff

                        if c == checksum:
                                print "\tSection size:0x%08X, checked crc:0x%08X" % (size2, checksum)
                        else:
                                print "\tCrc corrupted!"
                else:
                        print "\t*** Section has different header format ***"

                ptr += 10

def CalSectCrc(data):
        sections = unpack("<I", data[15:15+4])[0]
        ptr = 27
        
        print "[+]Patching section CRC..."
        for i in range(sections):
                section = data[ptr:ptr+10]
                type, offset, size = unpack("<HII", section)
                # print "0x%04X: at offset 0x%08X, size 0x%08X [ends at 0x%08X]" %\
                #         (type, offset, size, offset+size)
                if type == 0xc002:
                        print "\tUnknown header type C002 ignored..."
                        ptr+=10
                        continue
                section_data = data[offset:offset+size]
                c = (crc32(section_data[:24] + "\0"*4 + section_data[28:], \
                           0xFFFFFFFF)^0xFFFFFFFF) & 0xffffffff
                print "\tCalculated crc: %s" % ("0x%08X" % c)
                
                section_data = section_data[:24] + pack("<I", c) + section_data[28:]
                data = data[:offset] + section_data + data[offset+size:]

                ptr+=10
                
        return data
                          
def CalMainCrc(data):
        '''
        recalculate main CRC
        '''
        
        c = (crc32(data[:23] + "\0"*4 + data[27:], 0xFFFFFFFF)^0xFFFFFFFF) & 0xffffffff        
        data = data[:23] + pack("<I", c) + data[27:]
        print "[+]Patching main crc: %s" % ("0x%08X" % c)

        return data

def SearchPatch(data, string, patch_string):
        '''
        simple string searching and patching
        '''
        assert len(string) == len(patch_string)
        length = len(string)
        index = data.find(string)
        while index > 0:
                print "[+]Found string %s at %s" % (repr(string), hex(index))
                data = data[:index] + patch_string + data[index+length:]
                print "[+]Patched with '%s'" % repr(patch_string)
                index = data.find(string)
        return data
        
        
def Patch(filename):

        f = open(filename, 'r+')
        Patched = f.read()

        Patched = VersionNumPatch(Patched, "10.6.3304")

        text1 = TextPad("No new texts, check back in a few.") #patch the empty text string for test
        text2 = TextPad("pwned by ------------- mongo&b0n0n")
        Patched = SearchPatch(Patched, text1, text2)
        
        Patched = CalSectCrc(Patched) # recalculate the section CRCs
        Patched = CalMainCrc(Patched) # recalculate the main CRC

        with open('FirmwareUpdate.Patch', 'w+') as f:
                f.write(Patched)

Patch("FirmwareUpdate.bin")
# ChkMainCrc("FirmwareUpdate.Patch")
# ChkSectCrc("FirmwareUpdate.Patch")


