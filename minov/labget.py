from .dns_handler import  *
from .http_handler import *

# from .tls_beta import * # uncommented for my own tls
import re
import sys
import os

############## some common methods for minor operation


"""
This method wraps the logic to process proper redirection(with cookie) a.t. the code contained in the http header
"""
def request(url):
    code=302;
    current_url=url; # set the initial state
    global_cookie=[]; # maintain a global cookie only
    while(code==302 or code==301):
        # parse the url
        protocol_name=protocol(current_url);
        if(protocol_name=='http'):
            outcome=parse_http_url(current_url);
        else:
            outcome=parse_https_url(current_url);
        # look up the dns, which prints the extended environment information
        ips= dns_lookup(outcome['host']);
        print('Request %s' % current_url);
        print(ips);
        assert(len(ips)>0);
        ip= ips[0];
        # set default port number
        port=80 if protocol_name=='http' else 443;
        # set the custom port number if any
        if(outcome['port']):
            port= int(outcome['port']);
        if(protocol_name=='http'):
            response=http_GET_req(ip, port, outcome['host'], outcome['path'], outcome['params'],refine_cookie(global_cookie));
        else:
            # the crypto logic is little beyond my understanding right now. Thus the implementation process of TLS paused
            response=https_GET_req(ip, port, outcome['host'], outcome['path'], outcome['params'], refine_cookie(global_cookie)); # which is based on the python ssl library
            # begin of my own handshake, which is still a beta and incomplete version, thus try catch it
            # uncommented for my own unfinished version of tls
            # try:
            #     tls_handshake(ip, port);
            #     sys.stderr.write('TLS Implementation Incomplete. Currently, to Certificate Verification Stage \n');
            # except Exception:
            #     pass;
        # print the header information
        print(response['header']);
        code=int(response['header']['code']);
        # if some cookie contained in the response, just append it to the global cookie stack
        if('set-cookie' in response['header']['params']):
            global_cookie.append(response['header']['params']['set-cookie']);
        # if a next hop is expected, modify the current url
        if(code==302 or code==301):
            current_url = refine_redirect_path(current_url, response['header']['params']['location']);
    # if still code larger than 400
    if(code>=400):
        sys.stderr.write('Code %d when Req %s\n' % (code, current_url));
    return response['body'];


"""
@param: url is where the protocol name contained, if not, by default http
which will determine whether the target is a https request or a http request
"""
def protocol(url):
    pattern=re.compile("^(?P<protocol>\w+)://[\s|\S]+$");
    m=pattern.match(url);
    if(m==None or m.group('protocol')==None):
        return "http";
    return m.group('protocol').lower();


"""
a trivial method to ensemble the cookie array, since there may be several set-cookie responses in the redirection chain
"""
def refine_cookie(global_cookie):
    if(len(global_cookie)==0):
        return None;
    else:
        return ';'.join(global_cookie);

"""
a method deals with relative redirection or global redirection
"""
def refine_redirect_path(current_url, redirection):
    pattern=re.compile("^(?P<protocol>\w+)://[\s|\S]+$");
    m=pattern.match(redirection);
    if(m==None):
        return os.path.join(current_url.rstrip('/'),redirection.lstrip('/'));
    else:
        return redirection;


if __name__=='__main__':
    # test_url="http://elearning.fudan.edu.cn/portal/site/05eb92ef-a124-427d-a407-58da918e71c9"; # test http redirectioin with cookie maintained
    # test_url="https://github.com/"; # test for https
    # test_url="http://cn.bing.com/cnhp/life?IID=SERP.5046&IG=F38E2A233E58494FB9152D5636D9FC4D"; # gzipped
    # test_url="http://www.fudan.edu.cn/2016/index.html"; # basic test
    # test_url="http://cn.bing.com/fd/ls/GLinkPing.aspx?IG=9816C94C22EB4CEC9825D665E9DC34CE&ID=SERP,5097.1"; # for chunked
    assert(len(sys.argv)>=2);
    obj=request(sys.argv[1]);
    print(obj);
