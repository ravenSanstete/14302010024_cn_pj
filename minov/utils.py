"""
a tool method to encode a string array with a map function
"""
import functools
import socket
import time
import struct
import ssl
BUF_SIZE=96*1024; # 64k is enough?
BLOCK_SIZE=2*1024;

def encode_array(arr,charset='utf-8'):
    return list(map(lambda s:s.encode(charset),arr));

# basically, for array of byte seq concat
def concat(arr):
    return functools.reduce(lambda x,y:x+y, arr);



def buffered_tcp(ip, port, data):
    tcp_skt=socket.socket(socket.AF_INET, socket.SOCK_STREAM);
    tcp_skt.connect((ip, port));
    tcp_skt.send(data);
    #  init a big buffer and then read data from server in a block convention
    chunks = [];
    bytes_recd = 0;
    time.sleep(5);
    while bytes_recd < BUF_SIZE:
        try:
            chunk = tcp_skt.recv(min(BUF_SIZE - bytes_recd, BLOCK_SIZE),socket.MSG_DONTWAIT);
            if chunk == b'':
                print("socket connection finished");
                break;
            chunks.append(chunk);
            bytes_recd = bytes_recd + len(chunk);
        except BlockingIOError:
            break;
    return b''.join(chunks);

def buffered_ssl(ip, port, data):
    ssl_skt=ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM));
    ssl_skt.connect((ip, port));
    ssl_skt.send(data);
    #  init a big buffer and then read data from server in a block convention
    ssl_skt.settimeout(20);
    chunks = [];
    bytes_recd = 0;
    # ssl_skt.settimeout(10);
    while bytes_recd < BUF_SIZE:
        try:
            chunk = ssl_skt.recv(min(BUF_SIZE - bytes_recd, BLOCK_SIZE));
            if chunk == b'':
                print("socket connection finished");
                break;
            chunks.append(chunk);
            bytes_recd = bytes_recd + len(chunk);
        except BlockingIOError:
            break;
    return b''.join(chunks);



"""
a method for padding, basically for struct unpack usage
"""
def padding(byte_arr, pad_len, head=True):
    ctrl='!%dB'% (pad_len);
    return struct.pack(ctrl, 0)+byte_arr if head else byte_arr+struct.pack(ctrl,0);

def bytes2int(bytes):
    return int.from_bytes(bytes, 'big');

"""
@param: str with the format ([\w])
"""
def parse_params(p_str):
    if(p_str==None):
        return None;
    out={};
    p_str=p_str.split('&');
    for param in p_str:
        param=param.strip();
        if(param.strip()==''):
            continue;
        param=param.split('=');
        assert(len(param)==2);
        out[param[0]]=param[1];
    return out;

def ensemble_params(params):
    if(params==None):
        return '';
    str='';
    for k in params:
        str+='%s=%s&' %(k, params[k]);
    return str[:-1];


# which accept an array of
def str_to_bytes(str):
    pass;
