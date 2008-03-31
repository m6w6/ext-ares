/*
    +--------------------------------------------------------------------+
    | PECL :: ares                                                       |
    +--------------------------------------------------------------------+
    | Redistribution and use in source and binary forms, with or without |
    | modification, are permitted provided that the conditions mentioned |
    | in the accompanying LICENSE file are met.                          |
    +--------------------------------------------------------------------+
    | Copyright (c) 2006, Michael Wallner <mike@php.net>                 |
    +--------------------------------------------------------------------+
*/

/* $Id$ */

#ifndef PHP_ARES_H
#define PHP_ARES_H

extern zend_module_entry ares_module_entry;
#define phpext_ares_ptr &ares_module_entry

#define PHP_ARES_VERSION "0.7.0-dev"

#ifdef ZTS
#include "TSRM.h"
#endif

#endif /* PHP_ARES_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
