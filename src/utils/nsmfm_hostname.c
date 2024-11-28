#include <ngx_core.h>
#include <ngx_string.h>
#include "nsmfm_hostname.h"

#if (NGX_PCRE)
ngx_regex_t *nsmfm_validate_hostname_regex = NULL;
#endif

ngx_int_t nsmfm_init_hostname_regex(ngx_conf_t *cf) {
#if (NGX_PCRE)
    ngx_regex_compile_t rc;

    u_char errstr[NGX_MAX_CONF_ERRSTR];

    ngx_str_t pattern = ngx_string("(?!^.{253,}$)(?:(^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$|(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\\.)+[a-zA-Z]{2,6}$)|(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)))");

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern = pattern;
    rc.pool = cf->pool;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;
    rc.options = NGX_REGEX_CASELESS;

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
        return NGX_ERROR;
    }

    nsmfm_validate_hostname_regex = rc.regex;
#endif
    return NGX_OK;
}

ngx_int_t nsmfm_validate_hostname(ngx_str_t *str) {
#if (NGX_PCRE)
    if (str == NULL) {
        return NGX_ERROR;
    }
    if (str->data == NULL || str->len > 253 || str->len <= 0) {
        return NGX_ERROR;
    }
    if (nsmfm_validate_hostname_regex == NULL) {
        return NGX_OK;
    }
    return ngx_regex_exec(nsmfm_validate_hostname_regex, str, NULL, 0) >= 0;
#else
    return NGX_OK;
#endif
}
