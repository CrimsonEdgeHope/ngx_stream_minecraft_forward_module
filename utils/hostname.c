#include <ngx_core.h>
#include <ngx_string.h>
#include <stdbool.h>
#include "./hostname.h"
#include "../ngx_stream_minecraft_forward_module.h"

bool nsmfm_validate_hostname(ngx_str_t *str) {
    if (str == NULL) {
        return false;
    }
    if (str->data == NULL || str->len > 253 || str->len <= 0) {
        return false;
    }

#if (NGX_PCRE)
    if (nsmfm_validate_hostname_regex == NULL) {
        return NGX_OK;
    }
    return ngx_regex_exec(nsmfm_validate_hostname_regex, str, NULL, 0) >= 0;
#else
    return true;
#endif
}
