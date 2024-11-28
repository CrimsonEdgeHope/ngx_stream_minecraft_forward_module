#ifndef _NSMFM_HOSTNAME_UTILS_
#define _NSMFM_HOSTNAME_UTILS_

#include <ngx_string.h>

#if (NGX_PCRE)
extern ngx_regex_t *nsmfm_validate_hostname_regex;
#endif

ngx_int_t nsmfm_init_hostname_regex(ngx_conf_t *cf);

ngx_int_t nsmfm_validate_hostname(ngx_str_t *str);

#endif
