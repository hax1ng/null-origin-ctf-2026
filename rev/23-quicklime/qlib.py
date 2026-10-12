import struct, hashlib

# ---- ELF vaddr reader ----
def elf_reader(path):
    d=open(path,"rb").read()
    e_phoff=struct.unpack_from("<Q",d,0x20)[0]
    e_phentsize=struct.unpack_from("<H",d,0x36)[0]
    e_phnum=struct.unpack_from("<H",d,0x38)[0]
    segs=[]
    for i in range(e_phnum):
        off=e_phoff+i*e_phentsize
        p_type=struct.unpack_from("<I",d,off)[0]
        p_offset,p_vaddr=struct.unpack_from("<QQ",d,off+8)
        p_filesz=struct.unpack_from("<Q",d,off+32)[0]
        if p_type==1: segs.append((p_vaddr,p_offset,p_filesz))
    def read(vaddr,n):
        for v,o,fs in segs:
            if v<=vaddr<v+fs:
                fo=o+(vaddr-v); return d[fo:fo+n]
        raise Exception("unmapped "+hex(vaddr))
    return read

R = elf_reader("quicklime")

# ---- constants ----
DOM=b"NULL0RIGIN/REV/CASCADE/v1"
TAG=b"23-quicklime"
BLK=0x23000
RTAB="reduction_tables.bin"

def sha(b): return hashlib.sha256(b).digest()

# reduction table block reader (mmap-ish via file seek)
_rt=open(RTAB,"rb")
def src_of_idx(idx):
    idx&=0x7ff
    _rt.seek(idx*BLK)
    return sha(_rt.read(BLK))

# ---- descriptors ----
DESC0=0x48f108
def desc_addr(k): return DESC0+(k-1)*0xd0   # k=1..5
def header(k):
    a=desc_addr(k)-8
    b=R(a,8)
    r14=struct.unpack_from("<I",b,0)[0]
    idx=struct.unpack_from("<I",b,4)[0]
    return r14,idx
def Dk(k): return R(desc_addr(k),32)              # SHA256(T_k)
def answer_bits(k,bytecount): return R(desc_addr(k)+0x20,bytecount)

S0=sha(DOM+b"|transcript|"+TAG)

def Tk(k, S_prev, SRC):
    c=bytes([0x30+k])
    return sha(DOM+b"|stage="+TAG+b"|layer="+c+b"|t="+S_prev+b"|src="+SRC)

if __name__=="__main__":
    for k in range(1,6):
        print("stage",k,"header",header(k),"D=",Dk(k).hex()[:16])
    print("S0=",S0.hex())
    # validate model: brute idx_1 to match D_1
    D1=Dk(1)
    found=[]
    for idx in range(2048):
        SRC=src_of_idx(idx)
        if sha(Tk(1,S0,SRC))==D1:
            found.append(idx)
    print("idx_1 matches:",found)
