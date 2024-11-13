/* realmd -- Realm Kerberos helper functions used by tools as well
 *
 * Copyright 2024 Red Hat Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 *
 * Author: Sumit Bose <sbose@redhat.com>
 */

#include "config.h"

#ifndef __REALM_KERBEROS_HELPER_H__
#define __REALM_KERBEROS_HELPER_H__

#include <string.h>
#include <sys/param.h>
#include <krb5/krb5.h>


const char *realm_krb5_get_error_message (krb5_context ctx,
                                          krb5_error_code code);

#endif /* __REALM_KERBEROS_HELPER_H__ */
