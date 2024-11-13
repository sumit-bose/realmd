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

#include "realm-kerberos-helper.h"

const char *realm_krb5_get_error_message (krb5_context ctx,
                                          krb5_error_code code)
{
	static char out[4096];
	const char *tmp;
	size_t len;

	tmp = krb5_get_error_message (ctx, code);
	len = strlen (tmp);
	memcpy (out, tmp, MIN (sizeof (out), len));
	out[sizeof(out) - 1] = '\0';
	krb5_free_error_message (ctx, tmp);

	return out;
}
