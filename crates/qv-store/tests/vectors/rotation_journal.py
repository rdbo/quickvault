# SPDX-License-Identifier: AGPL-3.0-or-later

"""Independent development journal vector (public zero/one VKs; stdlib only)."""
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
b={0:1,1:uuid(0x11),2:uuid(0x22),3:bytes([0x33])*16,4:1,5:2,6:7,7:8,8:bytes([0x66])*32,9:bytes([0x77])*32,10:bytes([0x44])*16,11:bytes([0x55])*16,12:bytes([0x88])*32}
t=cbor(['qv/rotation-journal/v1',cbor(b)])
for vk,gen,name in [(bytes(32),1,'old'),(bytes([255])*32,2,'new')]:
    prk=hmac.digest(b[2],vk,'sha512')
    info=cbor(['qv/purpose/v1','local-state',gen,1])
    key=hmac.digest(prk,info+b'\1','sha512')[:32]
    tag=hmac.digest(key,t,'sha512')[:32]
    expected = {'old': '6e719a530472cdf5864ec9823c5502740631b380c227647ec548a42e2f3f417c', 'new': '6f51b5b34fb68e777ab80b5511036fb389526d598e3c93bc6dcb7b30669cee4a'}
    assert tag.hex() == expected[name]
    b[13 if gen==1 else 14]=tag
# The journal transcript above was fixed before adding either MAC.
fixture = Path(__file__).with_name('rotation-journal.cbor')
if sys.argv[1:] == ['--write']:
    fixture.write_bytes(cbor(b))
else:
    assert not sys.argv[1:], 'usage: rotation_journal.py [--write]'
    assert fixture.read_bytes() == cbor(b)
print('rotation journal independent vector: ok')
