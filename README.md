# ngx_http_upstream_least_time

# Directive

least_time
-------------
* Syntax: 	least_time header | last_byte [inflight];
* Default: 	—
* Context: 	upstream

A load balancing method by the least average response time

If the header parameter is specified, time to receive the response header is
used. If the last_byte parameter is specified, time to receive the full
response is used. If the inflight parameter is specified, incomplete requests
are also taken into account. 


