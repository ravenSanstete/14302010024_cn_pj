import sys
import socket
import struct
import os




DNS_IP='202.120.224.26';
DNS_PORT=53;
BUF_SIZE=1024;

DNS_HEADER_SIZE=12;
CLASS_IN=1;


"""
put the dns format here as a reference
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR:0|   0000 |AA:0|TC:0|RD:1|RA:0| 000 |  0000 |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    1                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    0                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    0                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    0                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

# RD set because we want the recursive service

"""

# only list those that in the textbook
QTYPE_DICT={
    "A":1,
    "NS":2,  # haven't find the resource data format yet
    "CNAME":5
}



"""
@param  dns_ip: string, that specifies the dns host we want to ask
@param  auth: string, the question we want to raise(auth is passed from high-level, assumed to be well defined)
@param  qtype: string, the type of the question, should raise those exist in the qtype_dict
@return a byte request that can be transmitted by UDP
"""
def build_dns_request(auth,qtype):
    query_id=os.urandom(2);  # generate a 2-byte id
    header=query_id+struct.pack('!BBHHHH',1,0,1,0,0,0); # fill in the information on line 2
    assert(qtype in QTYPE_DICT);
    question=convert_addr(auth)+struct.pack('!HH',QTYPE_DICT[qtype],CLASS_IN);
    return header+question;



"""
a.t. RFC 1035
QNAME           a domain name represented as a sequence of labels, where
                each label consists of a length octet followed by that
                number of octets.  The domain name terminates with the
                zero length octet for the null label of the root.  Note
                that this field may be an odd number of octets; no
                padding is used.
@param auth: string, the domain name
@return byte seq satisfying the QNAME format
"""
def convert_addr(auth):
    labels=auth.encode('ascii').split(b'.');
    results=[];
    assert(len(list(filter(lambda x:len(x)>63, labels)))==0);
    for label in labels:
        results.append(bytes([len(label)]));
        results.append(label);
    results.append(b'\0'); #the zero legth octet for the null label
    return b''.join(results);







"""

"""
def dns_lookup(auth):
    dns_info=(DNS_IP, DNS_PORT);
    # create a udp socket
    udp_skt=socket.socket(socket.AF_INET, socket.SOCK_DGRAM);
    data_len=udp_skt.sendto(build_dns_request(auth,"A"),dns_info);
    recv_data=udp_skt.recvfrom(BUF_SIZE)[0];
    udp_skt.close();
    return dns_find_answer(auth,dns_parse(recv_data));


"""
@param auth, str a question raised by the upper layer
@param env, the environment constructed by parsing the result
@return ip address
"""
def dns_find_answer(auth, env):
    auth=auth.lower();
    print(env);
    while(not auth in env['A']):
        auth=env['CNAME'][auth];
    return env['A'][auth];





"""
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
"""

"""
@param d

@note: if rcode not zero, it means some error happens, stderr and then return None
"""

def dns_parse(d_gram):
    out=dns_parse_header(d_gram[:DNS_HEADER_SIZE]);
    # which means the response error
    if(out['RCODE']!=0):
        dns_response_err(out['RCODE']);
        return None;
    # begin to parse the body, since the response is correct
    body=d_gram[DNS_HEADER_SIZE:];
    # try to skip the answer part
    # init the pointer from the start of the body
    labels_cache={}; # this is used as a fast pointer find cache
    env={
        'A':{},
        'CNAME':{},
        'NS':{}
    }
    # for the pointer, just minus 12 and then find the ptr in the labels cahce
    ptr=0;
    for i in range(out['QDCOUNT']):
        ptr,label=dns_parse_labels(ptr, body,labels_cache);
        ptr+=4  # skip the defined length type and class part

    # now begin to parse the body
    for i in range(out['ANCOUNT']):
        ptr, result=dns_parse_answer(ptr, body, labels_cache);
        dns_extend_env(result,env);

    # now begin to parse the body
    for i in range(out['NSCOUNT']):
        ptr, result=dns_parse_answer(ptr, body, labels_cache);
        dns_extend_env(result,env);

    # now begin to parse the body
    for i in range(out['ARCOUNT']):
        ptr, result=dns_parse_answer(ptr, body, labels_cache);
        dns_extend_env(result,env);
    return env;


"""
a small method for putting into the environment the result and without causing any conflict
"""
def dns_extend_env(result, env):
    k=result[0].decode('utf-8').lower();
    v=result[1].decode('utf-8').lower();
    if(result[2]=='CNAME' or result[2]=='NS'):
        env[result[2]][k]=v;
    else:
        if(k in env[result[2]]):
            env[result[2]][k].append(v);
        else:
            env[result[2]][k]=[v];






"""
@param ptr: int, ptr to the label len octet
@param d_gram: the env to do the parsing

@return (n_ptr, label_str) n_ptr: the new ptr position. label string, the label
"""
def dns_parse_labels(ptr, d_gram, labels_cache):
    old_ptr=ptr;
    results=[];
    label=b'';
    current_length=0;
    first_potential_ptr=False; # if it is a totally ptr label, it will be false at the end of this subroutine
    # begin iteration
    while(ptr<len(d_gram)):
        if(current_length<=0):
            results.append(label); # push it into the stack
            label=b''; # reinit the label
            # test whether it is a ptr or a length
            if(dns_test_ptr(d_gram[ptr])):
                name_ptr=(struct.unpack('!H',d_gram[ptr:ptr+2])[0]&0x3FFF)-DNS_HEADER_SIZE;
                if(not name_ptr in labels_cache):
                    # which means it should be a fragment
                    for k in labels_cache:
                        if(k<name_ptr and name_ptr<k+len(labels_cache[k])):
                            anchor=name_ptr-k;
                            results.append(labels_cache[k][anchor:]);
                            break;
                else:
                    results.append(labels_cache[name_ptr]);
                ptr+=2;
                break;
            else:
                current_length=d_gram[ptr];
            first_potential_ptr=True;
            # test the end byte \0
            if(current_length==0):
                ptr+=1;
                break;
        else:
            label+=bytes([d_gram[ptr]]); # meet the label components
            current_length-=1;
        ptr+=1;
    results=results[1:];

    out=b'.'.join(results);
    if(first_potential_ptr):
        labels_cache[old_ptr]=out;
    return ptr,out;



"""
@param ptr: int, ptr to the label len octet
@param d_gram: the str that should be parsed
@param labels_cache: like the environment in a parser

@return (n_ptr,(resources)) n_ptr: the new ptr position, if A, resources (name,ip) CNAME (name,name)
@Note: update the label cache as well as find a new label
"""

def dns_parse_answer(ptr, d_gram, labels_cache):
    result=[];
    # first parse the name
    n_ptr,label=dns_parse_labels(ptr, d_gram, labels_cache); # put the parsed out label into the cache
    result.append(label); # put the result as the key
    ptr=n_ptr;

    # then do the other information
    (qtype, qclass, ttl, r_data_len)=struct.unpack('!HHIH',d_gram[ptr:ptr+10]);
    ptr+=10;
    assert(qclass==CLASS_IN);

    if(qtype==QTYPE_DICT['CNAME']):
        n_ptr,label=dns_parse_labels(ptr, d_gram, labels_cache); # parse out the label
        result.append(label);
        result.append('CNAME');
        ptr=n_ptr;
    elif(qtype==QTYPE_DICT['A']):
        result.append(byte_to_addr(d_gram[ptr:ptr+4]));
        result.append('A');
        ptr+=4;
    elif(qtype==QTYPE_DICT['NS']):
        n_ptr,label=dns_parse_labels(ptr, d_gram, labels_cache); # parse out the label
        result.append(label);
        result.append('NS');
        ptr=n_ptr;
    else:
        pass;
    return (ptr,result);



"""
@param b: 1 octet to be tested
@return  true if it is a ptr
"""

def dns_test_ptr(b):
    is_ptr=(b>>6)&0x2;
    return (is_ptr==0x2);



"""
@param bbbb: the 4 byte
"""
def byte_to_addr(bbbb):
    results=[];
    for b in bbbb:
        results.append(str(b).encode('utf-8'));
    return b'.'.join(results);



"""
@param d_gram: byte array,parse out the header information that is useful information for future usage
@return (AA,Rcode,QDcount, ANcount, NScount, ARcount) in a dict
"""
def dns_parse_header(head):
    (line_1,line_2,qd_c,an_c,ns_c,ar_c)=struct.unpack('!HHHHHH',head);
    aa=(line_2>>10)&0x1;
    rcode=line_2&0xF;
    return {
        'AA':aa,
        'RCODE':rcode,
        'QDCOUNT':qd_c,
        'ANCOUNT':an_c,
        'NSCOUNT':ns_c,
        'ARCOUNT':ar_c
    }

"""
@param rcode: 4bit integer, parsed out from the response
@return void
stderr corresponding error
"""


DNS_ERR_DICT={
    1:'FORMAT ERROR',
    2:'SERVER FAILURE',
    3:'NAME ERROR',
    4:'NOT IMPLEMENTED',
    5:'REFUSED'
}

def dns_response_err(rcode):
    sys.stderr.write(DNS_ERR_DICT[rcode]);
    return;
