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

#include "realm.h"
#include "realm-dbus-constants.h"
#include "realm-dbus-generated.h"

#include <glib.h>
#include <glib/gi18n.h>

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

static RealmDbusRealm *
locate_configured_matching_realm (RealmClient *client,
                                  const gchar *realm_name)
{
	RealmDbusProvider *provider;
	const gchar *const *paths;
	RealmDbusRealm *realm = NULL;
	gboolean matched;
	gint i;

	provider = realm_client_get_provider (client);
	paths = realm_dbus_provider_get_realms (provider);

	for (i = 0; paths && paths[i]; i++) {
		matched = FALSE;

		realm = realm_client_get_realm (client, paths[i]);
		if (realm != NULL) {
			matched = (realm_name == NULL ||
			           g_strcmp0 (realm_dbus_realm_get_name (realm), realm_name) == 0) &&
			           realm_is_configured (realm);
		}

		if (matched)
			break;

		g_object_unref (realm);
		realm = NULL;
	}

	if (realm == NULL) {
		if (!realm_name)
			realm_handle_error (NULL, "Couldn't find a configured realm");
		else
			realm_handle_error (NULL, "Couldn't find a matching realm");
		return NULL;
	}

	return realm;
}

static int
perform_permit_specific (RealmClient *client,
                         const gchar *realm_name,
                         const gchar **logins,
                         gint n_logins,
                         gboolean withdraw,
                         gboolean names_are_groups)
{
	RealmDbusRealm *realm;
	SyncClosure sync;
	gchar **add_or_remove;
	GError *error = NULL;
	const gchar *empty[] = { NULL };
	GVariant *options;

	realm = locate_configured_matching_realm (client, realm_name);
	if (realm == NULL)
		return 1;

	/* Make it null terminated */
	add_or_remove = g_new0 (gchar *, n_logins + 1);
	memcpy (add_or_remove, logins, sizeof (gchar *) * n_logins);

	sync.result = NULL;
	sync.loop = g_main_loop_new (NULL, FALSE);

	options = realm_build_options ("groups", names_are_groups,
	                               NULL);
	g_variant_ref_sink (options);

	realm_dbus_realm_call_change_login_policy (realm, REALM_DBUS_LOGIN_POLICY_PERMITTED,
	                                           withdraw ? empty : (const gchar * const*)add_or_remove,
	                                           withdraw ? (const gchar * const*)add_or_remove : empty,
	                                           options, NULL, on_complete_get_result, &sync);

	g_variant_unref (options);

	/* This mainloop is quit by on_complete_get_result */
	g_main_loop_run (sync.loop);

	realm_dbus_realm_call_change_login_policy_finish (realm, sync.result, &error);

	g_object_unref (sync.result);
	g_main_loop_unref (sync.loop);
	g_object_unref (realm);

	if (error != NULL) {
		realm_handle_error (error, _("Couldn't change permitted logins"));
		return 1;
	}

	return 0;
}

static int
perform_logins_all (RealmClient *client,
                    const gchar *realm_name,
                    gboolean permit)
{
	RealmDbusRealm *realm;
	SyncClosure sync;
	const gchar *policy;
	const gchar *logins[] = { NULL };
	GError *error = NULL;
	GVariant *options;

	realm = locate_configured_matching_realm (client, realm_name);
	if (realm == NULL)
		return 1;

	sync.result = NULL;
	sync.loop = g_main_loop_new (NULL, FALSE);

	options = realm_build_options (NULL, NULL);
	g_variant_ref_sink (options);

	policy = permit ? REALM_DBUS_LOGIN_POLICY_REALM : REALM_DBUS_LOGIN_POLICY_DENY;
	realm_dbus_realm_call_change_login_policy (realm, policy,
	                                           (const gchar * const *)logins,
	                                           (const gchar * const *)logins,
	                                           options, NULL, on_complete_get_result, &sync);

	/* This mainloop is quit by on_complete_get_result */
	g_main_loop_run (sync.loop);

	realm_dbus_realm_call_change_login_policy_finish (realm, sync.result, &error);

	g_variant_unref (options);
	g_object_unref (sync.result);
	g_main_loop_unref (sync.loop);
	g_object_unref (realm);

	if (error != NULL) {
		realm_handle_error (error, _("Couldn't change permitted logins"));
		return 1;
	}

	return 0;
}

static int
realm_permit_or_deny (RealmClient *client,
                      gboolean permit,
                      int argc,
                      char *argv[])
{
	GOptionContext *context;
	gboolean arg_all = FALSE;
	gboolean arg_groups = FALSE;
	gboolean arg_withdraw = FALSE;
	gchar *realm_name = NULL;
	GError *error = NULL;
	gint ret = 2;

	/* This implements the deprecated commands */

	GOptionEntry option_entries[] = {
		{ "all", 'a', 0, G_OPTION_ARG_NONE, &arg_all,
		  permit ? N_("Permit any realm account login") : N_("Deny any realm account login"), NULL },
		{ "realm", 'R', 0, G_OPTION_ARG_STRING, &realm_name, N_("Realm to permit/deny logins for"), NULL },
		{ NULL, }
	};

	GOptionEntry option_entries_permit[] = {
		{ "withdraw", 'x', 0, G_OPTION_ARG_NONE, &arg_withdraw,
		  N_("Withdraw permit for a realm account to login"), NULL },
		{ "groups", 'g', 0, G_OPTION_ARG_NONE, &arg_groups,
		  N_("Treat names as groups which to permit"), NULL },
		{ NULL, }
	};

	context = g_option_context_new ("realm");
	g_option_context_set_translation_domain (context, GETTEXT_PACKAGE);
	g_option_context_add_main_entries (context, option_entries, NULL);
	if (permit) {
		g_option_context_add_main_entries (context, option_entries_permit, NULL);
	}
	g_option_context_add_main_entries (context, realm_global_options, NULL);

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		realm_print_error ("%s", error->message);
		g_error_free (error);

	} else if (arg_all && argc != 1) {
		realm_print_error (_("No logins should be specified with -a or --all"));

	} else if (!permit && arg_withdraw) {
		realm_print_error (_("The --withdraw or -x arguments cannot be used when denying logins"));

	} else if (arg_all && arg_withdraw) {
		realm_print_error (_("Specific logins must be specified with --withdraw"));

	} else if (arg_all && arg_groups) {
		realm_print_error (_("Groups may not be specified with -a or --all"));

	} else if (arg_all) {
		ret = perform_logins_all (client, realm_name, permit);

	} else if (argc < 2) {
		if (!permit)
			realm_print_error (_("Use --all to deny all logins"));
		else
			realm_print_error (_("Specify specific users to add or remove from the permitted list"));

	} else {
		if (!permit) {
			realm_print_error (_("Specifying deny without --all is deprecated. Use realm permit --withdraw"));
			arg_withdraw = TRUE;
		}

		ret = perform_permit_specific (client, realm_name,
		                               (const gchar **)(argv + 1),
		                               argc - 1, arg_withdraw, arg_groups);
	}

	g_free (realm_name);
	g_option_context_free (context);
	return ret;
}

int
realm_permit (RealmClient *client,
              int argc,
              char *argv[])
{
	return realm_permit_or_deny (client, TRUE, argc, argv);
}

int
realm_deny (RealmClient *client,
            int argc,
            char *argv[])
{
	return realm_permit_or_deny (client, FALSE, argc, argv);
}
