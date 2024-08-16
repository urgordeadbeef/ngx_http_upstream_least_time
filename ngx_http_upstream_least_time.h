
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_LEAST_TIME_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_LEAST_TIME_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

enum {
    NGX_LEAST_TIME_HEADER = 1,
    NGX_LEAST_TIME_LAST_BYTE = 2,
    NGX_LEAST_TIME_INFLIGHT_BYTES = 3,
};

typedef struct {
    ngx_uint_t config;
} ngx_http_upstream_least_time_conf_t;

typedef struct ngx_http_upstream_least_time_peer_s   ngx_http_upstream_least_time_peer_t;

struct ngx_http_upstream_least_time_peer_s {
    ngx_http_upstream_rr_peer_t		 *rr;
    ngx_http_upstream_least_time_peer_t  *next;
    ngx_msec_t				  avg_time;
    size_t				  n;

    NGX_COMPAT_BEGIN(32)
    NGX_COMPAT_END
};

typedef struct ngx_http_upstream_least_time_peers_s  ngx_http_upstream_least_time_peers_t;

struct ngx_http_upstream_least_time_peers_s {
    ngx_http_upstream_rr_peers_t	  *rr;

    ngx_http_upstream_least_time_peers_t   *next;
    ngx_http_upstream_least_time_peer_t    *peer;
};

#if (NGX_HTTP_UPSTREAM_ZONE)
typedef struct {
    ngx_http_upstream_least_time_peers_t *peers;
    ngx_http_upstream_main_conf_t        *cf;
    ngx_http_upstream_srv_conf_t	 *u;
    ngx_shm_zone_init_pt		  init;
    void                                 *data;
} ngx_http_upstream_least_time_zone_t;
#endif

typedef struct {
    ngx_http_upstream_least_time_peers_t   *peers;
    ngx_http_upstream_least_time_peer_t    *current;
    ngx_http_request_t			   *request;
    ngx_http_upstream_rr_peer_data_t	   *rrp;
} ngx_http_upstream_least_time_peer_data_t;

ngx_int_t ngx_http_upstream_init_least_time(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_http_upstream_init_least_time_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_least_time_peer(ngx_peer_connection_t *pc,
    void *data);
void ngx_http_upstream_free_least_time_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);


#endif /* _NGX_HTTP_UPSTREAM_LEAST_TIME_H_INCLUDED_ */
