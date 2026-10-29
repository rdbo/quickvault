# SPDX-License-Identifier: AGPL-3.0-or-later

"""Independent development snapshot-inventory vector (public all-one VK; stdlib only)."""
from pathlib import Path
import sys
import hashlib, hmac

def cbor(x):
    def head(m,n):
        if n<24:return bytes([m*32+n])
        for a,w in [(24,1),(25,2),(26,4),(27,8)]:
            if n<1<<(8*w):return bytes([m*32+a])+n.to_bytes(w,'big')
    if isinstance(x,int):return head(0,x)
    if isinstance(x,bytes):return head(2,len(x))+x
    if isinstance(x,str):return head(3,len(x.encode()))+x.encode()
    if isinstance(x,list):return head(4,len(x))+b''.join(map(cbor,x))
    return head(5,len(x))+b''.join(cbor(k)+cbor(v) for k,v in sorted(x.items()))
def uuid(byte):
    x=bytearray([byte]*16);x[6]=(x[6]&15)|64;x[8]=(x[8]&63)|128;return bytes(x)
rows=[[bytes([0x10])*16,1,1_700_000_000_000,1234,bytes([0xab])*32],
      [bytes([0x20])*16,1,1_700_000_360_000,99,bytes([0xcd])*32]]
b={0:1,1:uuid(0x22),2:2,3:rows}
t=cbor(['qv/snapshot-inventory/v1',cbor(b)])
vk=bytes([255])*32
prk=hmac.digest(b[1],vk,'sha512')
info=cbor(['qv/purpose/v1','local-state',2,1])
key=hmac.digest(prk,info+b'\1','sha512')[:32]
tag=hmac.digest(key,t,'sha512')[:32]
expected='f73d24e019e2f9d129db32fc7203c6d1f27f09c60efd1856c9694477697be30c'
assert tag.hex() == expected, tag.hex()
b[4]=tag
fixture = Path(__file__).with_name('snapshot-inventory.cbor')
if sys.argv[1:] == ['--write']:
    fixture.write_bytes(cbor(b))
    print(tag.hex())
else:
    assert not sys.argv[1:], 'usage: snapshot_inventory.py [--write]'
    assert fixture.read_bytes() == cbor(b)
    print('snapshot inventory independent vector: ok')
