import re
import time
from .utils import *
from .dns_handler import  *
import sys
import gzip
import io


def http_GET_req(host_ip, port ,host, path, params=None, cookie=None):
    # init the socket
    if(path.strip()==''):
        path='/';
    header= http_build_GET_request(host, refine_path(path, params), cookie);
    # since a minimal get request, no body data is needed
    req_obj=http_parse_req(buffered_tcp(host_ip, port, header));
    return req_obj;


"""
A trivial method to apeend the parameters to the path
"""
def refine_path(path, params):
    if(params==None):
        return path;
    else:
        return '%s?%s' % (path, ensemble_params(params));


# begin work at the HTTP part, currently only accept the
def http_build_GET_request(host, path, cookie):
    params=dict();
    params['Host']=host;
    params['Connection']='keep-alive';
    params['Accept']='text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8';
    params['User-Agent']='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.95 Safari/537.36';
    params['Cache-Control']='no-cache';
    params['Accept-Language']='ja,en-US;q=0.8,en;q=0.6';
    params['Accept-Encoding']='gzip, deflate, sdch';
    # if the cookie field is not None, just set it, which is mostly used for redirection response
    if(cookie!=None):
        params['Cookie']=cookie;
    return b'\r\n'.join([http_build_top_line('GET', path), http_build_header_from_dict(params),b'',b'']);

def http_build_top_line(method, path, version='HTTP/1.1', charset='utf-8'):
    return b' '.join(encode_array([method, path, version]));

"""
@param o: dict type object, no limited on the content of it
@Bev.  build a http header according to the dict without omitting any information
"""
def http_build_header_from_dict(o,charset='utf-8'):
    lines=[];
    for key in o:
        lines.append(b':'.join(encode_array([key, o[key]])));
    return b'\r\n'.join(lines);



"""
@param req: a byte string to be parsed
@return (header, data, )
"""

def http_parse_req(req, charset='utf-8'):
    split_ptr=http_split(req);
    header=http_parse_header(req[:split_ptr].decode(charset));
    body=req[split_ptr+2:];
    # check length if provided
    if('content-length' in header['params']):
        assert(int(header['params']['content-length'])==len(body)); # if assert failure, broken pipe
    # process the chunked data
    if('transfer-encoding' in header['params']):
        if(header['params']['transfer-encoding']=='chunked'):
            body=http_parse_chunked(body);

    # process the gzipped data
    if('content-encoding' in header['params']):
        if(header['params']['content-encoding']=='gzip'):
            body=http_gunzip(body);
        else:
            sys.stderr.write('Unknown Coding');
            body=b'';
    # only decode the text type data
    if('content-type' in header['params']):
        major, minor= http_parse_content_type(header['params']['content-type']);
        if(major=='text'):
            body=body.decode(charset);
    return {
        'header': header,
        'body': body
    }


"""
a small method that deal with the chunked http response, which operates on the original bytes stream of the http
@ return: data in a byte array form
"""
def http_parse_chunked(body):
    length_stack='';
    buf=b'';
    assert(len(body)>=4 and body[-4:]==b'\x0d\x0a\x0d\x0a'); # else broken pipe, the data is not
    ptr=0;
    while(ptr<len(body)-2):
        # meeting the control pattern
        if(body[ptr:ptr+2]==b'\x0d\x0a'):
            ptr+=2;
            chunk_size=int(length_stack,16);
            buf+=body[ptr:ptr+chunk_size];
            ptr+=chunk_size+2; # forward the current chunk and skip the chunk data boudary
            length_stack=''; # clear the stack
        # meet the size pattern
        else:
            length_stack+=chr(body[ptr]);
            ptr+=1;
    return buf;



# the raw bytes of req to find the '0x0d0a0d0a'
# return the next position after this pattern
def http_split(req):
    for i in range(len(req)):
        if(req[i:i+4]==b'\x0d\x0a\x0d\x0a'):
            return i+2;
    return -1;


# a simple wrapper for gzipped body file
def http_gunzip(body_bytes):
    return gzip.GzipFile(fileobj=io.BytesIO(body_bytes)).read();


"""
@param header_str: the http response header, the first line is not omitted actually
@return dict: (version, code, status, params)
"""

def http_parse_header(header_str):
    lines=header_str.split('\r\n');
    lines=lines[:-1];
    assert(len(lines)>0);
    tokens=lines[0].split(' ');
    lines=lines[1:];
    print(lines[0]);
    assert(len(tokens)>=3);
    tokens[2]=' '.join(tokens[2:]);
    tokens=tokens[:3]; # do a refine
    obj=dict();
    for line in lines:
        params = line.split(':',1);
        assert(len(params)==2);
        obj[params[0].lower()]=params[1].strip();
    return {
        'version': tokens[0],
        'code':tokens[1],
        'status':tokens[2],
        'params':obj
    };







#  add some length check for the hostname in the future
"""
@param: str (a string is required)
@return: (host,port,path-abempty,param-obj) in a dict

"""
def parse_http_url(str):
    pattern=re.compile("^http://(?P<auth>[\w.-]+)(:(?P<port>[\d]*))?(?P<abempty>(/[\w.-]*)*)(\?(?P<params>([\w]+=[\w+-{}']*&?)*))?$",re.I);
    m=pattern.match(str);
    return {
        'host':m.group('auth'),
        'port':m.group('port'),
        'path':m.group('abempty'),
        'params':parse_params(m.group('params'))
    };




"""
get major/minor, a trivial tool method
@return major,minor
"""
def http_parse_content_type(content_type):
    tokens=content_type.split('/');
    assert(len(tokens)==2);
    return tokens[0],tokens[1];





"""
We implement a ssl connector based on the ssl library for completeness, since the custom version of tls-beta is still under
implementation
"""

def https_GET_req(host_ip, port, host, path, params=None, cookie=None):
    # init the socket
    if(path.strip()==''):
        path='/';
    header= http_build_GET_request(host, refine_path(path, params), cookie);
    req_obj=http_parse_req(buffered_ssl(host_ip, port, header));
    return req_obj;

#  add some length check for the hostname in the future
"""
@param: str (a string is required)
@return: (host,port,path-abempty) in a dict

"""
def parse_https_url(str):
    pattern=re.compile("^https://(?P<auth>[\w.-]+)(:(?P<port>[\d]*))?(?P<abempty>(/[\w.-]*)*)(\?(?P<params>([\w]+=[\w+-{}']*&?)*))?$",re.I);
    m=pattern.match(str);
    return {
        'host':m.group('auth'),
        'port':m.group('port'),
        'path':m.group('abempty'),
        'params':parse_params(m.group('params'))
    };
