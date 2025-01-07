/* realmd -- Realm configuration service
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

#include "realm.h"
#include "realm-client.h"
#include "realm-dbus-constants.h"
#include "realm-dbus-generated.h"

#include <glib.h>
#include <glib/gi18n.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

typedef struct {
	GAsyncResult *result;
	GMainLoop *loop;
} SyncClosure;

static void
on_complete_get_result (GObject *source,
                        GAsyncResult *result,
                        gpointer user_data)
{
	SyncClosure *sync = user_data;
	sync->result = g_object_ref (result);
	g_main_loop_quit (sync->loop);
}

static int
call_renew (RealmDbusKerberosMembership *membership,
            GVariant *options,
            GError **error)
{
	SyncClosure sync;
	gboolean ret;

	sync.result = NULL;
	sync.loop = g_main_loop_new (NULL, FALSE);

	/* Start actual operation */
	realm_dbus_kerberos_membership_call_renew (membership, options, NULL,
	                                           on_complete_get_result, &sync);

	/* This mainloop is quit by on_complete_get_result */
	g_main_loop_run (sync.loop);

	ret = realm_dbus_kerberos_membership_call_renew_finish (membership, sync.result, error);

	g_object_unref (sync.result);
	g_main_loop_unref (sync.loop);

	return ret ? 0 : 1;
}

typedef struct {
	gchar *membership_software;
	gboolean use_ldaps;
	gboolean add_samba_data;
	gchar *computer_password_lifetime;
	gchar *host_keytab;
	gchar *host_fqdn;
} RealmRenewArgs;

static void
realm_renew_args_clear (gpointer data)
{
	RealmRenewArgs *args = data;
	g_free (args->membership_software);
}

static int
perform_renew (RealmClient *client,
               const gchar *string,
               RealmRenewArgs *args)
{
	RealmDbusKerberosMembership *membership;
	gboolean had_mismatched = FALSE;
	RealmDbusRealm *realm;
	GError *error = NULL;
	GVariant *options;
	GList *realms;
	gint ret;

	realms = realm_client_discover (client, string, args->use_ldaps, NULL,
	                                NULL, args->membership_software,
	                                REALM_DBUS_KERBEROS_MEMBERSHIP_INTERFACE,
	                                &had_mismatched, &error);

	if (error != NULL) {
		realm_handle_error(error, NULL);
		return 1;
	} else if (realms == NULL) {
		if (had_mismatched)
			realm_handle_error (NULL, _("Cannot renew credentials for this realm"));
		else
			realm_handle_error(NULL, _("No such realm found"));
		return 1;
	}

	membership = realms->data;
	realm = realm_client_to_realm (client, membership);
	if (!realm_is_configured (realm)) {
		realm_handle_error (NULL, _("Not joined to this domain"));
		return 1;
	}

	options = realm_build_options (REALM_DBUS_OPTION_MEMBERSHIP_SOFTWARE, args->membership_software,
	                               REALM_DBUS_OPTION_COMPUTER_PWD_LIFETIME, args->computer_password_lifetime,
	                               REALM_DBUS_OPTION_HOST_KEYTAB, args->host_keytab,
	                               REALM_DBUS_OPTION_HOST_FQDN, args->host_fqdn,
	                               REALM_DBUS_OPTION_USE_LDAPS, args->use_ldaps ? "True" : "False",
	                               REALM_DBUS_OPTION_ADD_SAMBA_DATA, args->add_samba_data ? "True" : "False",
	                               NULL);
	g_variant_ref_sink (options);

	ret = call_renew (membership, options, &error);
	if (error != NULL) {
		realm_handle_error (error, _("Couldn't renew realm credentials"));
	}

	g_variant_unref (options);
	g_list_free_full (realms, g_object_unref);
	return ret;
}

int
realm_renew (RealmClient *client,
             int argc,
             char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;
	const gchar *realm_name;
	RealmRenewArgs args = { 0 };
	GOptionGroup *group;
	gint ret = 0;

	GOptionEntry option_entries[] = {
		{ "membership-software", 0, 0, G_OPTION_ARG_STRING, &args.membership_software,
		  N_("Use specific membership software"), NULL },
		{ "use-ldaps", 0, 0, G_OPTION_ARG_NONE, &args.use_ldaps,
		  N_("Use ldaps to connect to LDAP"), NULL },
		{ "host-keytab", 0, 0, G_OPTION_ARG_STRING, &args.host_keytab,
		  N_("Path to the keytab"), NULL },
		{ "host-fqdn", 0, 0, G_OPTION_ARG_STRING, &args.host_fqdn,
		  N_("Fully-qualified name of the host"), NULL },
		{ "computer-password-lifetime", 0, 0, G_OPTION_ARG_STRING, &args.computer_password_lifetime,
		  N_("lifetime of the host accounts password in days"), NULL },
		{ "add-samba-data", 0, 0, G_OPTION_ARG_NONE, &args.add_samba_data,
		  N_("Try to update Samba's internal machine account password as well"), NULL },
		{ NULL, }
	};

	memset (&args, 0, sizeof (args));

	context = g_option_context_new ("renew REALM");
	g_option_context_set_translation_domain (context, GETTEXT_PACKAGE);

	group = g_option_group_new (NULL, NULL, NULL, &args, realm_renew_args_clear);
	g_option_group_add_entries (group, option_entries);
	g_option_group_add_entries (group, realm_global_options);
	g_option_context_set_main_group (context, group);

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		g_printerr ("%s: %s\n", g_get_prgname (), error->message);
		g_error_free (error);
		ret = 2;

	} else if (argc > 2) {
		g_printerr ("%s: %s\n", g_get_prgname (), _("Specify one realm to renew credentials"));
		ret = 2;

	} else {
		realm_name = argc < 2 ? "" : argv[1];
		ret = perform_renew (client, realm_name, &args);
	}

	g_option_context_free (context);
	return ret;
}
