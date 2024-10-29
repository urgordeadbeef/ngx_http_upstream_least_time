
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_upstream_least_time.h"


static char *ngx_http_upstream_least_time(ngx_conf_t *cf, ngx_command_t *cmd, 
    void *conf);
#if (NGX_HTTP_UPSTREAM_ZONE)
static ngx_int_t ngx_http_upstream_least_time_init_zone(
    ngx_shm_zone_t *shm_zone, void *data);
#endif

#if (NGX_HTTP_SSL)

static ngx_int_t ngx_http_upstream_empty_set_session(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_upstream_empty_save_session(ngx_peer_connection_t *pc,
    void *data);

#endif
static void *ngx_http_upstream_least_time_create_conf(ngx_conf_t *cf); 


static ngx_command_t  ngx_http_upstream_least_time_commands[] = {

    { ngx_string("least_time"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE12,
      ngx_http_upstream_least_time,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_least_time_module_ctx = {
    NULL,					/* preconfiguration */
    NULL,					/* postconfiguration */

    NULL,					/* create main configuration */
    NULL,					/* init main configuration */

    ngx_http_upstream_least_time_create_conf,   /* create server configuration */
    NULL,					/* merge server configuration */

    NULL,					/* create location configuration */
    NULL					/* merge location configuration */
};

ngx_module_t  ngx_http_upstream_least_time_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_least_time_module_ctx, /* module context */
    ngx_http_upstream_least_time_commands, /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_upstream_least_time_create_conf(ngx_conf_t *cf) 
{
    ngx_http_upstream_least_time_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(*conf));

    if (conf) {
	conf->config = NGX_CONF_UNSET;
    }

    return conf;
}   


static void
ngx_http_upstream_least_time_ref_peers(ngx_http_upstream_least_time_peers_t  *peers,
	ngx_http_upstream_rr_peers_t  *rrpeers)
{
    ngx_http_upstream_least_time_peer_t   *peer, **peerp;
    ngx_http_upstream_rr_peer_t		  *rrpeer;
    ngx_uint_t				   n;

    peer = peers->peer;

    peers->rr = rrpeers;
    peerp = &peers->peer;
    rrpeer = rrpeers->peer;

    for (n = 0; n < rrpeers->number; n++) {
	peer[n].rr = rrpeer;

	*peerp = &peer[n];
        peerp = &peer[n].next;
	rrpeer = rrpeer->next;
    }
}


ngx_int_t
ngx_http_upstream_init_least_time(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_uint_t                     n;
    ngx_http_upstream_server_t    *server;
    ngx_http_upstream_least_time_peer_t   *peer, **peerp;
    ngx_http_upstream_least_time_peers_t  *peers, *backup;
    
    ngx_http_upstream_rr_peers_t  *rrpeers, *rrbackup;
    ngx_http_upstream_rr_peer_t  *rrpeer;
    
    if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }


    us->peer.init = ngx_http_upstream_init_least_time_peer;
    rrpeers = us->peer.data;

    peers = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_least_time_peers_t));
    if (peers == NULL) {
	return NGX_ERROR;
    }

    peer = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_least_time_peer_t) * rrpeers->number);
    if (peer == NULL) {
	return NGX_ERROR;
    }

#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_http_upstream_main_conf_t  *umcf = ngx_http_conf_get_module_main_conf(
	cf, ngx_http_upstream_module);

    if (us->shm_zone) {
	if(us->shm_zone->init && us->shm_zone->data) {
	    ngx_http_upstream_least_time_zone_t *z = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_least_time_zone_t));
	    if (NULL == z) {
		return NGX_ERROR;
	    }
	    
	    z->init = us->shm_zone->init;
	    z->data = us->shm_zone->data;
	    z->u = us;
	    z->cf = umcf;
	    z->peers = peers;

	    us->shm_zone->init = ngx_http_upstream_least_time_init_zone;
	    us->shm_zone->data = z;
	}
    }
#endif    
    
    peers->peer = peer;
    ngx_http_upstream_least_time_ref_peers(peers, rrpeers);
    us->peer.data = peers;

    /* backup servers */

    rrbackup = rrpeers->next;

    if (!rrbackup) {
	return NGX_OK;
    }

    backup = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_least_time_peers_t));
    if (backup == NULL) {
	return NGX_ERROR;
    }

    peer = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_least_time_peer_t) * rrbackup->number);
    if (peer == NULL) {
	return NGX_ERROR;
    }
    
    backup->peer = peer;
    ngx_http_upstream_least_time_ref_peers(backup, rrbackup);
    peers->next = backup;

    return NGX_OK;
}


ngx_int_t
ngx_http_upstream_init_least_time_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_uint_t				       n;
    ngx_http_upstream_least_time_peer_data_t  *ltp = r->upstream->peer.data;

    if (NULL == ltp) {
	ltp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_least_time_peer_data_t));
	if (NULL == ltp) {
	    return NGX_ERROR;
	}
	ltp->rrp = NULL;
    } 
    
    r->upstream->peer.data = ltp->rrp;
    ltp->peers = us->peer.data;
    us->peer.data = ltp->peers->rr;

    if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }
       
    ltp->rrp = r->upstream->peer.data;
    r->upstream->peer.data = ltp;

    ltp->current = NULL;
    ltp->request = r;
    us->peer.data = ltp->peers;

    r->upstream->peer.get = ngx_http_upstream_get_least_time_peer;
    r->upstream->peer.free = ngx_http_upstream_free_least_time_peer;
    
    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_get_least_time_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_least_time_peer_data_t  *ltp = data;
    ngx_http_upstream_rr_peer_data_t  *rrp = ltp->rrp;

    time_t                         now;
    uintptr_t                      m;
    ngx_int_t                      rc, total;
    ngx_uint_t                     i, n, p, many;
    ngx_http_upstream_least_time_peer_t   *peer, *best;
    ngx_http_upstream_least_time_peers_t  *peers;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get least time peer, try: %ui", pc->tries);

    if (rrp->peers->single) {
        return ngx_http_upstream_get_round_robin_peer(pc, rrp);
    }

    pc->cached = 0;
    pc->connection = NULL;

    now = ngx_time();

    peers = ltp->peers;

    ngx_http_upstream_rr_peers_wlock(peers->rr);

    best = NULL;
    total = 0;

#if (NGX_SUPPRESS_WARN)
    many = 0;
    p = 0;
#endif

    for (peer = peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {
        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        if (rrp->tried[n] & m) {
            continue;
        }

        if (peer->rr->down) {
	    peer->ema = 0;
            continue;
        }

        if (peer->rr->max_fails
            && peer->rr->fails >= peer->rr->max_fails
            && now - peer->rr->checked <= peer->rr->fail_timeout)
        {
            continue;
        }

        if (peer->rr->max_conns && peer->rr->conns >= peer->rr->max_conns) {
            continue;
        }

        /*
         * select peer with least conns; if there are
         * multiple peers with the same conns, select
         * based on mininal avg response
         */
        if (best == NULL
            || peer->rr->conns * best->rr->weight < best->rr->conns * peer->rr->weight)
        {
            best = peer;
            many = 0;
            p = i;

        } else if (peer->rr->conns * best->rr->weight == best->rr->conns * peer->rr->weight) {
	    if (peer->ema && best->ema) {
		if (peer->ema < best->ema) {
		    best = peer;
		    many = 0;
		    p = i;
		} else if (peer->ema == best->ema) {
		    many = 1;
		}
	    } else if (!peer->ema && !best->ema) {
		many = 1;
	    } else if (peer->ema && !best->ema) {
		best = peer;
		many = 0;
		p = i;
	    }
        }
    }

    if (best == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get least time peer, no peer found");

        goto failed;
    }
    
    if (many) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get least time peer, many");

        for (peer = best, i = p;
             peer;
             peer = peer->next, i++)
        {
            n = i / (8 * sizeof(uintptr_t));
            m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

            if (rrp->tried[n] & m) {
                continue;
            }

            if (peer->rr->down) {
                continue;
            }

	    if (peer->ema * peer->rr->conns * best->rr->weight !=
		best->ema * best->rr->conns * peer->rr->weight)
	    {
                continue;
            }
	    
            if (peer->rr->max_fails
                && peer->rr->fails >= peer->rr->max_fails
                && now - peer->rr->checked <= peer->rr->fail_timeout)
            {
                continue;
            }

            if (peer->rr->max_conns && peer->rr->conns >= peer->rr->max_conns) {
                continue;
            }

            peer->rr->current_weight += peer->rr->effective_weight;
            total += peer->rr->effective_weight;

            if (peer->rr->effective_weight < peer->rr->weight) {
                peer->rr->effective_weight++;
            }

            if (peer->rr->current_weight > best->rr->current_weight) {
                best = peer;
                p = i;
            }
        }
    }

    best->rr->current_weight -= total;

    if (now - best->rr->checked > best->rr->fail_timeout) {
        best->rr->checked = now;
    }
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get least time peer %p c:%ui ema:%ui",
		   best, best->rr->conns, best->ema);

    pc->sockaddr = best->rr->sockaddr;
    pc->socklen = best->rr->socklen;
    pc->name = &best->rr->name;

    best->rr->conns++;

    rrp->current = best->rr;
    ltp->current = best;

    n = p / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

    rrp->tried[n] |= m;

    ngx_http_upstream_rr_peers_unlock(peers->rr);

    return NGX_OK;

failed:

    if (peers->next) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get least time peer, backup servers");

        rrp->peers = peers->rr->next;
	ltp->peers = peers->next;

        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        for (i = 0; i < n; i++) {
            rrp->tried[i] = 0;
        }

        ngx_http_upstream_rr_peers_unlock(peers->rr);

        rc = ngx_http_upstream_get_least_time_peer(pc, ltp);

        if (rc != NGX_BUSY) {
            return rc;
        }

        ngx_http_upstream_rr_peers_wlock(peers->rr);
    }

    ngx_http_upstream_rr_peers_unlock(peers->rr);

    pc->name = peers->rr->name;

    return NGX_BUSY;
}

static inline void
ngx_http_upstream_least_time_avg(ngx_http_upstream_least_time_peer_t *peer, ngx_msec_t time)
{
    peer->ema = (ngx_msec_t)(((double)time * EMA_FACTOR) + ((double)peer->ema * (1 - EMA_FACTOR)));
}

void
ngx_http_upstream_free_least_time_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_upstream_least_time_peer_data_t  *ltp = data;

    time_t				  now;
    ngx_http_upstream_least_time_peer_t  *peer;
    ngx_http_upstream_t			 *u;
    ngx_uint_t				  inflight;
    ngx_event_pipe_t			 *p;
    ngx_msec_t				  avg;
    ngx_msec_t				  rsptime;

    peer = ltp->current;
    u = ltp->request->upstream;
    p = u->pipe;

    ngx_http_upstream_least_time_conf_t *ltcf = ngx_http_conf_upstream_srv_conf(u->conf->upstream, 
	    ngx_http_upstream_least_time_module);
    
    ngx_http_upstream_free_round_robin_peer(pc, ltp->rrp, state);
    inflight = !(p->upstream_done || (p->upstream_eof && p->length == -1));

    ngx_http_upstream_rr_peer_lock(ltp->peers->rr, peer->rr);

    rsptime = u->state->response_time;

    switch (ltcf->config) {
    case NGX_TTFB:
	ngx_http_upstream_least_time_avg(peer, u->state->header_time);
	rsptime = u->state->header_time;
	break;
    case NGX_TTLB:
	if (!inflight) {
	    ngx_http_upstream_least_time_avg(peer, u->state->response_time);
	}
	break;
    case NGX_TTLB_INFLIGHT:
	ngx_http_upstream_least_time_avg(peer, u->state->response_time);
	break;
    default:
	break;
    }
    ngx_http_upstream_rr_peer_unlock(ltp->peers->rr, peer->rr);

    ngx_log_debug6(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free least time peer %p c:%ui ema:%ui cfg:%ui i:%ui t:%ui",
		   peer, peer->rr->conns, peer->ema, ltcf->config, inflight, rsptime);
}

#if (NGX_HTTP_UPSTREAM_ZONE)
static ngx_int_t
ngx_http_upstream_least_time_init_zone(ngx_shm_zone_t *shm_zone, void *data) 
{
    ngx_http_upstream_least_time_peers_t   *peers, *backup;
    ngx_http_upstream_rr_peers_t	   *rr;
    ngx_http_upstream_least_time_peer_t    *peer;
    ngx_http_upstream_least_time_zone_t	   *z = shm_zone->data;
    ngx_slab_pool_t			   *shpool;

    z->u->peer.data = z->peers->rr;
    shm_zone->data = z->data;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        z->u->peer.data = shpool->data;
	return NGX_OK;
    }

    if (z->init(shm_zone, data) == NGX_ERROR) {
	return NGX_ERROR;
    }

    rr = z->peers->rr;

    peers = ngx_slab_alloc(shpool, sizeof(ngx_http_upstream_least_time_peers_t));
    if (peers == NULL) {
	return NGX_ERROR;
    }
    ngx_memzero(peers, sizeof(ngx_http_upstream_least_time_peers_t));

    peer = ngx_slab_alloc(shpool, sizeof(ngx_http_upstream_least_time_peer_t) * rr->number);
    if (peer == NULL) {
	return NGX_ERROR;
    }
    ngx_memzero(peer, sizeof(ngx_http_upstream_least_time_peer_t) * rr->number);

    peers->peer = peer;
    ngx_http_upstream_least_time_ref_peers(peers, rr);

    z->u->peer.data = z->peers = peers;
    shm_zone->data = z;
    shpool->data = peers;
    rr = z->peers->rr->next;

    if (!rr) {
	return NGX_OK;
    }

    backup = ngx_slab_alloc(shpool, sizeof(ngx_http_upstream_least_time_peers_t));
    if (backup == NULL) {
	return NGX_ERROR;
    }
    ngx_memzero(backup, sizeof(ngx_http_upstream_least_time_peers_t));

    peer = ngx_slab_alloc(shpool, sizeof(ngx_http_upstream_least_time_peer_t) * rr->number);
    if (peer == NULL) {
	return NGX_ERROR;
    }
    ngx_memzero(peer, sizeof(ngx_http_upstream_least_time_peer_t) * rr->number);

    backup->peer = peer;
    ngx_http_upstream_least_time_ref_peers(backup, rr);
    peers->next = backup;

    return NGX_OK;
}
#endif

static char *
ngx_http_upstream_least_time(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_least_time_conf_t *ltcf = conf;
    ngx_http_upstream_srv_conf_t  *uscf = ngx_http_conf_get_module_srv_conf(cf, 
	    ngx_http_upstream_module);

    if (ltcf->config != NGX_CONF_UNSET) { 
	return "is duplicate";
    }
    
    ngx_str_t *value = cf->args->elts;
    
    if (cf->args->nelts < 2 && cf->args->nelts > 3) {
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid format in \"%V\" directive", &cmd->name); 
	return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 2 && value[1].len == (sizeof("header") - 1) && 
	!ngx_strncmp(value[1].data, (u_char *)"header", sizeof("header") - 1)) {
	ltcf->config = NGX_TTFB;
    } else if (value[1].len == (sizeof("last_byte") - 1) &&
	       !ngx_strncmp(value[1].data, (u_char *)"last_byte", sizeof("last_byte") - 1)) {
	if (cf->args->nelts == 3 && value[2].len == (sizeof("inflight") - 1) &&
	    !ngx_strncmp(value[2].data, (u_char *)"inflight", sizeof("inflight") - 1)) {
	    ltcf->config = NGX_TTLB_INFLIGHT;
	} else {
	    ltcf->config = NGX_TTLB;
	}
    }

    if (cf->args->nelts < 2 && cf->args->nelts > 3 || ltcf->config == NGX_CONF_UNSET) {
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid format in \"%V\" directive", &cmd->name); 
	return NGX_CONF_ERROR;
    }

    if (uscf->peer.init_upstream) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->peer.init_upstream = ngx_http_upstream_init_least_time;

    uscf->flags = NGX_HTTP_UPSTREAM_CREATE
                  |NGX_HTTP_UPSTREAM_WEIGHT
                  |NGX_HTTP_UPSTREAM_MAX_CONNS
                  |NGX_HTTP_UPSTREAM_MAX_FAILS
                  |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |NGX_HTTP_UPSTREAM_DOWN
                  |NGX_HTTP_UPSTREAM_BACKUP;

    return NGX_CONF_OK;
}   

