# ngx_http_upstream_response_time

# Directive

least_response
-------------
* Syntax: 	least_response header | last_byte [inflight];
* Default: 	—
* Context: 	upstream

A load balancing method by the lowest average response time and the lowest
number of active connections

If the header parameter is specified, time to receive the response header is
used. If the last_byte parameter is specified, time to receive the full
response is used. If the inflight parameter is specified, incomplete requests
are also taken into account. 


