from rainbow.generics import rainbow_x64
import unicorn as uc
import struct
import random
import operator
import aes_dfa

import operator



def p32(x):
    return struct.pack("<I", x)

def p64(x):
    return struct.pack("<Q", x)

def u32(x):
    if len(x) != 4:
        x = x + "\x00"*(4-len(x))
    return struct.unpack("<I", x)[0]


e = rainbow_x64()

e.load("whitebox", typ=".elf")


e.emu.mem_map(0, 0x10000)

output = [] # 接收输出
fault = True # 注入标记，True时表示可注入
evtId = 0 # 位置标记
p = 0
# e.emu.mem_map(HEAP,HEAP_SIZE)
#
fault_arr = [0,0,0,0]
def hook_code(mu, address, size, user_data):
    global output
    # 拿到输出
    if address == 0x0400670:
        if e['rsi'] < 256:
            output.append(e['rsi'])


def get_diff(output, right_cipher):
    
    global fault_arr
    
    DIFF0 = [1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0]
    DIFF1 = [0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0]
    DIFF2 = [0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1]
    DIFF3 = [0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0]

    diff = []
    
    flag = False
    for i in range(16):
        if output[i] ^ right_cipher[i] > 0:
            diff.append(1)
        else:
            diff.append(0)
        
    if operator.eq(diff,DIFF0):
        fault_arr[0] = fault_arr[0]+1
        print("get group 0 fault cipher")
        flag = True
    if operator.eq(diff,DIFF1):
        fault_arr[1] = fault_arr[1]+1
        print("get group 1 fault cipher")
        flag = True
    if operator.eq(diff,DIFF2):
        fault_arr[2] = fault_arr[2]+1
        print("get group 2 fault cipher")
        flag = True
    if operator.eq(diff,DIFF3):
        fault_arr[3] = fault_arr[3]+1
        print("get group 3 fault cipher")
        flag = True
        
    return True


def should_fault(evtId, targetId, fault, address, size):
    return evtId > targetId and fault and size == 4


def hook_mem_access_fault(mu, access, address, size, value, user_data):
    global output, evtId, fault,p
    evtId += 1
    targetId = user_data[0]
    # 判断是否能够注入故障
    if access == uc.UC_MEM_READ:
        if should_fault(evtId, targetId, fault, address, size):
            print("FAULTING AT ", evtId)
            p = evtId
            fault = False
            bitfault = 1 << random.randint(0, 31)
            value = u32(mu.mem_read(address, size))
            nv = p32(value ^ bitfault)
            e[address + 0] = nv[0]
            e[address + 1] = nv[1]
            e[address + 2] = nv[2]
            e[address + 3] = nv[3]




target = [0]



def pyprints(emu):
    src = emu['rdi']
    i = 0
    c = emu[src]
    while c != b'\x00':
        i += 1
        c = emu[src+i]
    return True

e.stubbed_functions['printf'] = pyprints

def pyput(emu):
    src = emu['rdi']
    i = 0
    c = emu[src]
    while c != b'\x00':
        i += 1
        c = emu[src + i]
    return True

def pystrlen(emu):
    src = emu['rdi']
    i = 0
    c = emu[src]
    while c != b'\x00':
        i += 1
        c = emu[src + i]
    emu['rax'] = i
    return True


def pystrncmp(emu):
    a = emu['rdi']
    b = emu['rsi']
    n = emu['rdx']
    i = 0

    flag = 0
    for i in range(n):
        ar = emu[a+i]
        br = emu[b+i]
        if ar != br:
            flag = 1
            break
    if flag == 0:
        emu['rax'] = 0
    else:
        emu['rax'] = 1
    return True

def pystrncpy(emu):
    dest = emu['rdi']
    src = emu['rsi']
    n = emu['rdx']


    for i in range(n):
        c = emu[src + i][0]
        emu[dest + i] = c

    return True

e.stubbed_functions['puts'] = pyput
e.stubbed_functions['strlen'] = pystrlen
e.stubbed_functions['freopen'] = pystrlen
e.stubbed_functions['strncmp'] = pystrncmp
e.stubbed_functions['strncpy'] = pystrncpy


e.trace_reset()
e.mem_trace = False
e.function_calls = False
e.trace = 0

fd = open("faults.txt","wb",buffering=0)

# get the right cipher

input_buf = 0xCAFE1000
argv = 0xCAFE0000

e[input_buf] = b"0011223344556677"
e[argv + 8] = input_buf
e["rdi"] = 2  # argc
e["rsi"] = argv

e.start(0x4007D6, 0x0454FF8)
a = e.emu.hook_add(uc.UC_HOOK_CODE, hook_code)
e.start(0x0454FF8, 0)
e.emu.hook_del(a)

# 写入明文
for i in b"0011223344556677":
    fd.write("0x{:02x}".format(i)[2:].encode('utf-8'))
fd.write(b" ")

# 写入正确密文
for i in output:
    fd.write("0x{:02x}".format(i)[2:].encode('utf-8'))
fd.write(b"\n")

right_cipher = []

for i in output:
    right_cipher.append(i)

for tracenum in range(30):
    input_buf = 0xCAFE1000
    argv = 0xCAFE0000

    e[input_buf] = b"0011223344556677"
    e[argv + 8] = input_buf
    e["rdi"] = 2  # argc
    e["rsi"] = argv

    output = []
    target[0] = p
    evtId = 0
    fault = True

    b = e.emu.hook_add(uc.UC_HOOK_MEM_READ, hook_mem_access_fault, begin=0x682000,end=0x689000,user_data=target)
    e.start(0x4007D6, 0x0454FF8)
    a = e.emu.hook_add(uc.UC_HOOK_CODE, hook_code)
    e.start(0x0454FF8, 0)
    e.emu.hook_del(a)
    e.emu.hook_del(b)
    
    if len(output) == 16 and get_diff(output, right_cipher):
        # print(output)
        # 写入明文
        for i in b"0011223344556677":
            fd.write("0x{:02x}".format(i)[2:].encode('utf-8'))
        fd.write(b" ")
        
        # 写入故障密文
        for i in output:
            fd.write( "0x{:02x}".format(i)[2:].encode('utf-8'))
        fd.write(b"\n")
    
       
    if fault_arr[0] >= 2 and fault_arr[1] >= 2 and fault_arr[2] >= 2 and fault_arr[3] >=2:
        print("fault ciphers collect complete")
        break

fd.close()
aes_dfa.crack_file("faults.txt", verbose=2)
    
        
        
        