/* realmd -- Realm configuration service
 *
 * Copyright 2012 Red Hat Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 *
 * Author: Stef Walter <stefw@gnome.org>
 */

#include "config.h"

#ifndef __REALM_KERBEROS_MEMBERSHIP_H__
#define __REALM_KERBEROS_MEMBERSHIP_H__

#include <gio/gio.h>

#include <krb5/krb5.h>

#include "realm-credential.h"
#include "realm-dbus-generated.h"

G_BEGIN_DECLS

#define REALM_TYPE_KERBEROS_MEMBERSHIP             (realm_kerberos_membership_get_type ())
#define REALM_KERBEROS_MEMBERSHIP(inst)            (G_TYPE_CHECK_INSTANCE_CAST ((inst), REALM_TYPE_KERBEROS_MEMBERSHIP, RealmKerberosMembership))
#define REALM_IS_KERBEROS_MEMBERSHIP(inst)         (G_TYPE_CHECK_INSTANCE_TYPE ((inst), REALM_TYPE_KERBEROS_MEMBERSHIP))
#define REALM_KERBEROS_MEMBERSHIP_GET_IFACE(inst)  (G_TYPE_INSTANCE_GET_INTERFACE ((inst), REALM_TYPE_KERBEROS_MEMBERSHIP, RealmKerberosMembershipIface))

typedef struct _RealmKerberosMembership RealmKerberosMembership;
typedef struct _RealmKerberosMembershipIface RealmKerberosMembershipIface;

struct _RealmKerberosMembershipIface {
	GTypeInterface parent_iface;

	void       (* join_async)               (RealmKerberosMembership *realm,
	                                         RealmCredential *cred,
	                                         GVariant *options,
	                                         GDBusMethodInvocation *invocation,
	                                         GAsyncReadyCallback callback,
	                                         gpointer user_data);

	gboolean   (* join_finish)              (RealmKerberosMembership *realm,
	                                         GAsyncResult *result,
	                                         GError **error);

	const RealmCredential * (* join_creds)  (RealmKerberosMembership *realm);

	void       (* leave_async)              (RealmKerberosMembership *realm,
	                                         RealmCredential *cred,
	                                         GVariant *options,
	                                         GDBusMethodInvocation *invocation,
	                                         GAsyncReadyCallback callback,
	                                         gpointer user_data);

	gboolean   (* leave_finish)             (RealmKerberosMembership *realm,
	                                         GAsyncResult *result,
	                                         GError **error);

	const RealmCredential * (* leave_creds) (RealmKerberosMembership *realm);

	void       (* renew_async)              (RealmKerberosMembership *realm,
	                                         GVariant *options,
	                                         GDBusMethodInvocation *invocation,
	                                         GAsyncReadyCallback callback,
	                                         gpointer user_data);

	gboolean   (* renew_finish)             (RealmKerberosMembership *realm,
	                                         GAsyncResult *result,
	                                         GError **error);
};

GType               realm_kerberos_membership_get_type        (void) G_GNUC_CONST;

G_END_DECLS

#endif /* __REALM_KERBEROS_MEMBERSHIP_H__ */
