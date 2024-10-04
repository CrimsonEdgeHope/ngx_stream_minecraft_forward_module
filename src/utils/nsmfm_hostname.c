#include <ngx_core.h>
#include <ngx_string.h>
#include <stdbool.h>
#include "nsmfm_hostname.h"
#include "../main/ngx_stream_minecraft_forward_module.h"

bool nsmfm_validate_hostname(ngx_str_t *str) {
    if (str == NULL) {
        return false;
    }
    if (str->data == NULL || str->len > 253 || str->len <= 0) {
        return false;
    }

#if (NGX_PCRE)
    if (nsmfm_validate_hostname_regex == NULL) {
        return true;
    }
    return ngx_regex_exec(nsmfm_validate_hostname_regex, str, NULL, 0) >= 0;
#else
    return true;
#endif
}
