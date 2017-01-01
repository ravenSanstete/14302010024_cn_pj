## Minov.labget
ID. 14302010024

Welcome!
###### Usage
> cd /parent/dir/to/minov

> python3 -m minov.labget url

[Note: the url should agree on the url definition is _RFC 7230_]

###### What has been implemented
  (1) ipv4 DNS resolution
> strictly comply with _RFC 1035_, with a compact decompression algorithm for the dictionary-coding of labels. (sources in __'/dns\_handler.py'__)

  (2) http(https) url parsing
> a trivial function, which uses module _re_, included in __'/http\_handler.py'__ and __'/tls\_beta.py'__

  (3) http request construction & response parsing
> fundamental request and response processing

> (Bonus) gzip dealing, implemented in __'/http_handler.py'__ __http_parse_req()__ with external library gzip

> (Bonus) chunked transfer coding dealing, implemented in __'/http_handler.py'__ __http_parse_chunked()__

[Note: the chunked process is always before the gzip decoding process, which is of significant important]

> (Bonus) fulfilled http request header, implemented in __'/http_handler.py'__ __http_build_GET_request()__, which is richer than _wget_ header

> (Bonus) dealing with redirection and maintain the cookies, implemented in __'/lab_get.py'__ __ request(url)__, which considers the situation that several cookies to be set in a single redirection chain and both relative location and absolute location

(4)(Potential Bonus?) An unfinished TLS module
> 1.I have attempted to implement the TLS myself and the source code until now is in '/tls_beta.py'. It actually squeezes most of my time on this project with little outcome. __The current stage I'm working on is certificate verification__. Without a solid understanding of _RSA_ and other hash methods, the implementation of verification process stumbled.__(Although the certificate chain is built without any problems)__

> 2.The _labget_ module invokes the python library ssl for completeness and it also invokes the __'/tls_beta.py'__ __ tls_handshake(dst_ip, dst_port=443)__ to present the certificates and the server hello information in order to convince the current implementation.

###### Environment
1. MacOSX 10.12, with python3.5
2. Since the provided server is not quite stable, most of my tests are processed manually with wireshark, wget and my own labget to access some custom real-world urls, which are listed below.

>http://elearning.fudan.edu.cn/portal/site/05eb92ef-a124-427d-a407-58da918e71c9 \# for http redirection with cookie maintained

>https://github.com/ \#for https

> http://cn.bing.com/cnhp/life?IID=SERP.5046&IG=F38E2A233E58494FB9152D5636D9FC4D \# for gzipped body

> http://www.fudan.edu.cn/2016/index.html \# basic test

> http://cn.bing.com/fd/ls/GLinkPing.aspx?IG=9816C94C22EB4CEC9825D665E9DC34CE&ID=SERP,5097.1 \# for chunked

[Note: the behavior of my labget with these urls can be assumed to represent the promising behaviors of my implementation]

###### Finally
1. If you want to run my unfinished TLS, install an external python module for ASN1 parsing from https://github.com/etingof/pyasn1 (which is mostly for x509 parsing, and since pyasn1 itself is still under construction... ...). Also, a pycrypto package is needed, which is more mature.
2. Happy New Year, Geeks!
