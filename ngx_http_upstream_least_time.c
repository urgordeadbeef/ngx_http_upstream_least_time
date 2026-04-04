
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_HTTP_UPSTREAM_CHECK)
#include "ngx_http_upstream_check_module.h"
#endif

#include "ngx_http_upstream_least_time.h"

#define ngx_http_upstream_tries(p) ((p)->tries                                \
                                    + ((p)->next ? (p)->next->tries : 0))


static char *ngx_http_upstream_least_time(ngx_conf_t *cf, ngx_command_t *cmd, 
    void *conf);

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

#define GET_AVG_TIME(p) ((ngx_msec_t)((p)->spare[0]))
#define SET_AVG_TIME(p, t) (p)->spare[0] = t

ngx_int_t
ngx_http_upstream_init_least_time(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    
    if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    us->peer.init = ngx_http_upstream_init_least_time_peer;

    return NGX_OK;
}


ngx_int_t
ngx_http_upstream_init_least_time_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_least_time_peer_data_t *data = NULL;
    
    if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }
    data = ngx_palloc(r->pool, sizeof(ngx_http_upstream_least_time_peer_data_t));

    if (NULL == data) {
	return NGX_ERROR;
    }

    data->request = r;
    data->rrp = r->upstream->peer.data;
    r->upstream->peer.data = data;

    r->upstream->peer.get = ngx_http_upstream_get_least_time_peer;
    r->upstream->peer.free = ngx_http_upstream_free_least_time_peer;
    
    return NGX_OK;
}

static size_t
ngx_least_time_score(ngx_http_upstream_rr_peer_t *p)
{
    ngx_msec_t time = GET_AVG_TIME(p);
    size_t score;

    score = (1 + time) * (1 + p->conns/p->weight);

    return score;
}

static ngx_int_t
ngx_http_upstream_get_least_time_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_least_time_peer_data_t *d = data;
    ngx_http_upstream_rr_peer_data_t  *rrp = d->rrp;

    time_t                         now;
    uintptr_t                      m;
    ngx_int_t                      rc, total;
    ngx_uint_t                     i, n, p, many;
    ngx_http_upstream_rr_peer_t   *peer, *best;
    ngx_http_upstream_rr_peers_t  *peers;
    size_t			   pscore = 0, bscore = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get least time peer, try: %ui", pc->tries);

    if (rrp->peers->single) {
        return ngx_http_upstream_get_round_robin_peer(pc, rrp);
    }

    pc->cached = 0;
    pc->connection = NULL;

    now = ngx_time();

    peers = rrp->peers;

    ngx_http_upstream_rr_peers_wlock(peers);

#if (NGX_HTTP_UPSTREAM_ZONE)
    if (peers->config && rrp->config != *peers->config) {
        goto busy;
    }
#endif      

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

        if (peer->down) {
	    SET_AVG_TIME(peer, 1);
            continue;
        }

#if (NGX_HTTP_UPSTREAM_CHECK)
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                "get least time peer, check_index: %ui",
                peer->check_index);
    
        if (ngx_http_upstream_check_peer_down(peer->check_index)) {
	    SET_AVG_TIME(peer, 1);
            continue;
        }
#endif

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            continue;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            continue;
        }

        /*
         * select peer with least response time; if there are
         * multiple peers with the same response, select
         * based on round-robin
         */

	pscore = ngx_least_time_score(peer);	
	if (best) {
	    bscore = ngx_least_time_score(best);
	}

        if (best == NULL || pscore < bscore)
        {
            best = peer;
	    bscore = pscore;
            many = 0;
            p = i;

        } else if (pscore == bscore) {
            many = 1;
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

            if (peer->down) {
                continue;
            }

#if (NGX_HTTP_UPSTREAM_CHECK)
	    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
		    "get least time peer, check_index: %ui",
		    peer->check_index);
	
	    if (ngx_http_upstream_check_peer_down(peer->check_index)) {
		continue;
	    }
#endif
	    pscore = ngx_least_time_score(peer);	

	    if (pscore != bscore) {
		continue;
	    }

            if (peer->max_fails
                && peer->fails >= peer->max_fails
                && now - peer->checked <= peer->fail_timeout)
            {
                continue;
            }

            if (peer->max_conns && peer->conns >= peer->max_conns) {
                continue;
            }

            peer->current_weight += peer->effective_weight;
            total += peer->effective_weight;

            if (peer->effective_weight < peer->weight) {
                peer->effective_weight++;
            }

            if (peer->current_weight > best->current_weight) {
                best = peer;
                p = i;
            }
        }
    }

    best->current_weight -= total;

    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get least time peer %p response %ui score %uz", best, GET_AVG_TIME(best), bscore);

    pc->sockaddr = best->sockaddr;
    pc->socklen = best->socklen;
    pc->name = &best->name;

    best->conns++;

    rrp->current = best;

    n = p / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

    rrp->tried[n] |= m;

    ngx_http_upstream_rr_peers_unlock(peers);

    return NGX_OK;

failed:

    if (peers->next) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get least time peer, backup servers");

        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        for (i = 0; i < n; i++) {
            rrp->tried[i] = 0;
        }

        ngx_http_upstream_rr_peers_unlock(peers);

        rc = ngx_http_upstream_get_least_time_peer(pc, rrp);

        if (rc != NGX_BUSY) {
            return rc;
        }

        ngx_http_upstream_rr_peers_wlock(peers);
    }

#if (NGX_HTTP_UPSTREAM_ZONE)
busy:
#endif

    ngx_http_upstream_rr_peers_unlock(peers);

    pc->name = peers->name;

    return NGX_BUSY;
}

void
ngx_http_upstream_free_least_time_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_upstream_least_time_peer_data_t  *d = data;
    ngx_http_upstream_rr_peer_data_t  *rrp = d->rrp;

    time_t				  now;
    ngx_http_upstream_rr_peer_t		 *peer;
    ngx_http_upstream_t			 *u;
    ngx_uint_t				  inflight;
    ngx_event_pipe_t			 *p;

    peer = rrp->current;
    u = d->request->upstream;
    p = u->pipe;

    ngx_http_upstream_least_time_conf_t *ltcf = ngx_http_conf_upstream_srv_conf(u->conf->upstream, 
	    ngx_http_upstream_least_time_module);
    
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free least time peer %ui %ui response %ui", pc->tries, state, u->state->response_time);

    ngx_http_upstream_free_round_robin_peer(pc, rrp, state);
    inflight = !(p->upstream_done || (p->upstream_eof && p->length == -1));

    switch (ltcf->config) {
    case NGX_LEAST_TIME_HEADER:
	SET_AVG_TIME(peer, (u->state->header_time + GET_AVG_TIME(peer))/2);
	break;
    case NGX_LEAST_TIME_LAST_BYTE:
	if (!inflight) {
	    SET_AVG_TIME(peer, (u->state->response_time + GET_AVG_TIME(peer))/2);
	}
	break;
    case NGX_LEAST_TIME_INFLIGHT_BYTES:
	SET_AVG_TIME(peer, (u->state->response_time + GET_AVG_TIME(peer))/2);
	break;
    default:
	break;
    }
    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free least time peer %p  avg time %ui config %ui inflight %ui", 
		   peer, GET_AVG_TIME(peer), ltcf->config, inflight);
}

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
	ltcf->config = NGX_LEAST_TIME_HEADER;
    } else if (value[1].len == (sizeof("last_byte") - 1) &&
	       !ngx_strncmp(value[1].data, (u_char *)"last_byte", sizeof("last_byte") - 1)) {
	if (cf->args->nelts == 3 && value[2].len == (sizeof("inflight") - 1) &&
	    !ngx_strncmp(value[2].data, (u_char *)"inflight", sizeof("inflight") - 1)) {
	    ltcf->config = NGX_LEAST_TIME_INFLIGHT_BYTES;
	} else {
	    ltcf->config = NGX_LEAST_TIME_LAST_BYTE;
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

