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

#include "realm-daemon.h"
#include "realm-dbus-constants.h"
#include "realm-dbus-generated.h"
#include "realm-invocation.h"

#include <glib.h>
#include <glib/gi18n.h>

#include <polkit/polkit.h>

#include <string.h>

typedef struct {
	const gchar *interface;
	const gchar *method;
	const gchar *action_id;
	int options_param;
} InvocationMethod;

static InvocationMethod invocation_methods[] = {
	{ REALM_DBUS_PROVIDER_INTERFACE, "Discover", "org.freedesktop.realmd.discover-realm", 2 },
	{ REALM_DBUS_KERBEROS_MEMBERSHIP_INTERFACE, "Join", "org.freedesktop.realmd.configure-realm", 2 },
	{ REALM_DBUS_KERBEROS_MEMBERSHIP_INTERFACE, "Leave", "org.freedesktop.realmd.deconfigure-realm", 2 },
	{ REALM_DBUS_KERBEROS_MEMBERSHIP_INTERFACE, "Renew", "org.freedesktop.realmd.renew-realm", 1 },
	{ REALM_DBUS_REALM_INTERFACE, "Deconfigure", "org.freedesktop.realmd.deconfigure-realm", 1 },
	{ REALM_DBUS_REALM_INTERFACE, "ChangeLoginPolicy", "org.freedesktop.realmd.login-policy", 4 },
};

typedef struct {
	GCancellable *cancellable;
	gchar *identifier;
	const gchar *operation;
	const InvocationMethod *method;
} InvocationData;

typedef struct {
	guint watch;
	gchar *locale;
} InvocationClient;

static const GVariantType *asv_type = NULL;
static GObject *current_invocation = NULL;
static GQuark invocation_data_quark = 0;

/* These are protected by the mutex */
static GHashTable *invocation_clients = NULL;
static GHashTable *cancellables = NULL;
static PolkitAuthority *polkit_authority = NULL;
G_LOCK_DEFINE_STATIC (invocations);

#define PEER ":peer"

static void
on_cancellable_gone (gpointer user_data,
                     GObject *where_the_object_was)
{
	gchar *invocation_id = user_data;

	G_LOCK (invocations);

	g_hash_table_remove (cancellables, invocation_id);

	G_UNLOCK (invocations);
}

static void
invocation_data_free (void *data)
{
	InvocationData *invo = data;
	if (invo->cancellable)
		g_object_unref (invo->cancellable);
	g_free (invo->identifier);
	g_free (invo);
}

static void
on_client_vanished (GDBusConnection *connection,
                    const gchar *name,
                    gpointer user_data)
{
	g_debug ("client gone away: %s", name);

	G_LOCK (invocations);

	realm_daemon_release (name);
	g_hash_table_remove (invocation_clients, name);

	G_UNLOCK (invocations);
}

static InvocationClient *
lookup_or_register_client (const gchar *sender)
{
	InvocationClient *client;

	g_assert (sender != NULL);

	client = g_hash_table_lookup (invocation_clients, sender);
	if (!client) {
		client = g_new0 (InvocationClient, 1);
		if (!g_str_equal (sender, PEER)) {
			client->watch = g_bus_watch_name (G_BUS_TYPE_SYSTEM, sender,
			                                  G_BUS_NAME_WATCHER_FLAGS_NONE,
			                                  NULL, on_client_vanished, NULL, NULL);
			g_debug ("client using service: %s", sender);
		}
		g_hash_table_insert (invocation_clients, g_strdup (sender), client);
		realm_daemon_hold (sender);
	}

	return client;
}

static gboolean
on_idle_setup_client (gpointer user_data)
{
	gchar *sender = user_data;

	G_LOCK (invocations);

	lookup_or_register_client (sender);

	G_UNLOCK (invocations);

	return FALSE; /* don't call again */
}

static gchar *
extract_operation (GDBusMessage *message,
                   const InvocationMethod *method)
{
	gchar *operation = NULL;
	GVariant *params;
	GVariant *options;
	gint idx;

	if (!method->options_param)
		return NULL;

	params = g_dbus_message_get_body (message);
	idx = method->options_param - 1;

	if (g_variant_n_children (params) <= idx)
		return NULL;

	options = g_variant_get_child_value (params, idx);
	if (g_variant_is_of_type (options, asv_type)) {
		if (!g_variant_lookup (options, REALM_DBUS_OPTION_OPERATION, "&s", &operation))
			operation = NULL;
	}

	g_variant_unref (options);
	return operation;
}

static void
prepare_method_in_dbus_worker_thread (GDBusMessage *message,
                                      const gchar *sender)
{
	const InvocationMethod *invo_method;
	InvocationData *invo = NULL;
	const gchar *interface;
	const gchar *method;
	gchar *operation;
	gchar *key;
	gint i;

	g_assert (sender != NULL);

	interface = g_dbus_message_get_interface (message);

	/* Do no processing these interfaces */
	if (g_str_equal (interface, REALM_DBUS_SERVICE_INTERFACE) ||
	    g_str_equal (interface, DBUS_PROPERTIES_INTERFACE) ||
	    g_str_equal (interface, DBUS_INTROSPECTABLE_INTERFACE) ||
	    g_str_equal (interface, DBUS_PEER_INTERFACE))
		return;

	method = g_dbus_message_get_member (message);

	invo_method = NULL;
	for (i = 0; i < G_N_ELEMENTS (invocation_methods); i++) {
		if (g_str_equal (invocation_methods[i].interface, interface) &&
		    g_str_equal (invocation_methods[i].method, method)) {
			invo_method = invocation_methods + i;
			break;
		}
	}

	/* Find the operation id for this message */
	if (invo_method) {
		invo = g_new0 (InvocationData, 1);
		invo->method = invo_method;

		operation = extract_operation (message, invo_method);
		if (operation) {
			g_debug ("Using '%s' operation for method '%s' invocation on '%s' interface",
			         operation, method, interface);
			invo->identifier = g_strdup_printf ("%s %s", sender, operation);
			invo->operation = strchr (invo->identifier, ' ');
			g_assert (invo->operation != NULL);
			invo->operation++;
		} else {
			invo->identifier = g_strdup (sender);
			invo->operation = NULL;
		}
	}

	g_object_set_qdata_full (G_OBJECT (message), invocation_data_quark,
	                         invo, invocation_data_free);

	G_LOCK (invocations);

	/* Prepare a cancellable if desired */
	if (invo && invo->operation) {
		invo->cancellable = g_hash_table_lookup (cancellables, invo->identifier);
		if (invo->cancellable == NULL) {
			invo->cancellable = g_cancellable_new ();
			key = g_strdup (invo->identifier);
			g_hash_table_insert (cancellables, key, invo->cancellable);
			g_debug ("Registered cancellable for operation '%s'", operation);
			g_object_weak_ref (G_OBJECT (invo->cancellable), on_cancellable_gone, key);
		} else {
			g_object_ref (invo->cancellable);
		}
	}

	/* Setup a client later if necessary */
	if (g_hash_table_lookup (invocation_clients, sender) == NULL)
		g_idle_add_full (G_PRIORITY_DEFAULT, on_idle_setup_client, g_strdup (sender), g_free);

	G_UNLOCK (invocations);
}

static GDBusMessage *
on_connection_filter (GDBusConnection *connection,
                      GDBusMessage *message,
                      gboolean incoming,
                      gpointer user_data)
{
	const gchar *own_name = user_data;
	GDBusMessageType type;
	const gchar *sender;

	/* Each time we see an incoming function call, keep the service alive */
	if (incoming) {
		type = g_dbus_message_get_message_type (message);
		if (type == G_DBUS_MESSAGE_TYPE_METHOD_CALL) {
			sender = g_dbus_message_get_sender (message);
			g_return_val_if_fail (sender != NULL || realm_daemon_is_dbus_peer (), message);

			if (sender == NULL)
				sender = PEER;
			if (!own_name || g_strcmp0 (own_name, sender) != 0)
				prepare_method_in_dbus_worker_thread (message, sender);
		}
	}

	return message;
}

static gboolean
on_service_release (RealmDbusService *object,
                    GDBusMethodInvocation *invocation)
{
	const char *sender;

	sender = g_dbus_method_invocation_get_sender (invocation);
	g_return_val_if_fail (sender != NULL || realm_daemon_is_dbus_peer (), FALSE);

	if (sender == NULL)
		sender = PEER;

	g_debug ("explicitly releasing service: %s", sender);

	G_LOCK (invocations);

	g_hash_table_remove (invocation_clients, sender);
	realm_daemon_release (sender);

	G_UNLOCK (invocations);

	realm_dbus_service_complete_release (object, invocation);

	return TRUE;
}

static gboolean
on_service_cancel (RealmDbusService *object,
                   GDBusMethodInvocation *invocation,
                   const gchar *operation)
{
	GCancellable *cancellable;
	gchar *identifier;
	const gchar *sender;

	sender = g_dbus_method_invocation_get_sender (invocation);
	g_return_val_if_fail (sender != NULL || realm_daemon_is_dbus_peer (), FALSE);

	if (sender == NULL)
		sender = PEER;

	G_LOCK (invocations);

	identifier = g_strdup_printf ("%s %s", sender, operation);
	cancellable = g_hash_table_lookup (cancellables, identifier);
	g_free (identifier);

	if (cancellable)
		g_object_ref (cancellable);

	G_UNLOCK (invocations);

	realm_dbus_service_complete_cancel (object, invocation);

	if (cancellable) {
		g_debug ("Cancelling operation '%s'", operation);

		g_cancellable_cancel (cancellable);
		g_object_unref (cancellable);
	} else {
		g_debug ("Nothing to cancel for '%s'", operation);
	}

	return TRUE;
}

static gboolean
on_service_set_locale (RealmDbusService *object,
                       GDBusMethodInvocation *invocation,
                       const gchar *arg_locale)
{
	InvocationClient *client;
	const gchar *sender;

	sender = g_dbus_method_invocation_get_sender (invocation);
	g_return_val_if_fail (sender != NULL || realm_daemon_is_dbus_peer (), FALSE);

	if (sender == NULL)
		sender = PEER;

	G_LOCK (invocations);

	client = lookup_or_register_client (sender);
	g_free (client->locale);
	client->locale = g_strdup (arg_locale);

	G_UNLOCK (invocations);

	realm_dbus_service_complete_set_locale (object, invocation);
	return TRUE;
}

static void
unwatch_and_free_client (gpointer data)
{
	InvocationClient *client = data;

	g_assert (data != NULL);
	if (client->watch)
		g_bus_unwatch_name (client->watch);
	g_free (client->locale);
	g_free (client);

	realm_daemon_poke ();
}

void
realm_invocation_initialize (GDBusConnection *connection)
{
	RealmDbusService *service;
	const gchar *self_name;

	invocation_data_quark = g_quark_from_static_string ("realmd-invocation-data");
	asv_type = G_VARIANT_TYPE ("a{sv}");

	cancellables = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
	invocation_clients = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                            g_free, unwatch_and_free_client);

	/* Add a filter which keeps service alive */
	self_name = g_dbus_connection_get_unique_name (connection);
	g_dbus_connection_add_filter (connection, on_connection_filter,
	                              g_strdup (self_name), g_free);

	service = realm_dbus_service_skeleton_new ();
	g_signal_connect (service, "handle-release", G_CALLBACK (on_service_release), NULL);
	g_signal_connect (service, "handle-set-locale", G_CALLBACK (on_service_set_locale), NULL);
	g_signal_connect (service, "handle-cancel", G_CALLBACK (on_service_cancel), NULL);
	g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (service),
	                                  connection, REALM_DBUS_SERVICE_PATH, NULL);

}

void
realm_invocation_cleanup (void)
{
	g_hash_table_destroy (cancellables);
	cancellables = NULL;

	g_hash_table_destroy (invocation_clients);
	invocation_clients = NULL;

	g_clear_object (&polkit_authority);
}

static InvocationData *
lookup_invocation_data (GDBusMethodInvocation *invocation)
{
	InvocationData *invo;
	GDBusMessage *message;

	invo = g_object_get_qdata (G_OBJECT (invocation), invocation_data_quark);
	if (invo == NULL) {
		message = g_dbus_method_invocation_get_message (invocation);
		invo = g_object_get_qdata (G_OBJECT (message), invocation_data_quark);
		if (invo != NULL)
			g_object_set_qdata (G_OBJECT (invocation), invocation_data_quark, invo);
	}

	return invo;
}

static gboolean
check_dbus_action (const gchar *sender,
                   const gchar *action_id)
{
	PolkitAuthorizationResult *result;
	PolkitAuthority *authority;
	PolkitSubject *subject;
	GError *error = NULL;
	gboolean ret;

	/* If we're a dbus peer, just allow all calls */
	if (realm_daemon_is_dbus_peer ())
		return TRUE;

	g_return_val_if_fail (sender != NULL, FALSE);
	g_return_val_if_fail (action_id != NULL, FALSE);

	G_LOCK (invocations);

	authority = polkit_authority ? g_object_ref (polkit_authority) : NULL;

	G_UNLOCK (invocations);

	if (!authority) {
		authority = polkit_authority_get_sync (NULL, &error);
		if (authority == NULL) {
			g_warning ("failure to get polkit authority: %s", error->message);
			g_error_free (error);
			return FALSE;
		}

		G_LOCK (invocations);

		if (polkit_authority == NULL) {
			polkit_authority = g_object_ref (authority);

		} else {
			g_object_unref (authority);
			authority = g_object_ref (polkit_authority);
		}

		G_UNLOCK (invocations);
	}

	/* do authorization async */
	subject = polkit_system_bus_name_new (sender);
	result = polkit_authority_check_authorization_sync (authority, subject, action_id, NULL,
			POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION, NULL, &error);

	g_object_unref (authority);
	g_object_unref (subject);

	/* failed */
	if (result == NULL) {
		g_warning ("couldn't check polkit authorization%s%s",
		           error ? ": " : "", error ? error->message : "");
		g_error_free (error);
		return FALSE;
	}

	ret = polkit_authorization_result_get_is_authorized (result);
	g_object_unref (result);

	return ret;
}


gboolean
realm_invocation_authorize  (GDBusMethodInvocation *invocation)
{
	const gchar *action_id = NULL;
	const gchar *sender;
	InvocationData *invo;
	gboolean ret;

	invo = lookup_invocation_data (invocation);

	if (invo != NULL && invo->method != NULL)
		action_id = invo->method->action_id;

	if (action_id == NULL) {
		g_warning ("Couldn't authorize unregistered method '%s' on interface '%s'",
		           g_dbus_method_invocation_get_method_name (invocation),
		           g_dbus_method_invocation_get_interface_name (invocation));
		ret = FALSE;

	} else {
		sender = g_dbus_method_invocation_get_sender (invocation);
		ret = check_dbus_action (sender, action_id);
	}

	if (ret == FALSE) {
		g_debug ("rejecting access to method '%s' on interface '%s' at %s",
		         g_dbus_method_invocation_get_method_name (invocation),
		         g_dbus_method_invocation_get_interface_name (invocation),
		         g_dbus_method_invocation_get_object_path (invocation));
		g_dbus_method_invocation_return_dbus_error (invocation, REALM_DBUS_ERROR_NOT_AUTHORIZED,
		                                            _("Not authorized to perform this action"));
	}

	return ret;
}

GCancellable *
realm_invocation_get_cancellable (GDBusMethodInvocation *invocation)
{
	InvocationData *invo;
	g_return_val_if_fail (invocation != NULL, NULL);
	invo = lookup_invocation_data (invocation);
	return invo ? invo->cancellable : NULL;
}

const gchar *
realm_invocation_get_operation (GDBusMethodInvocation *invocation)
{
	InvocationData *invo;
	g_return_val_if_fail (invocation != NULL, NULL);
	invo = lookup_invocation_data (invocation);
	return invo ? invo->operation : NULL;
}

const gchar *
realm_invocation_get_key (GDBusMethodInvocation *invocation)
{
	InvocationData *invo;
	g_return_val_if_fail (invocation != NULL, NULL);
	invo = lookup_invocation_data (invocation);
	return invo ? invo->identifier : NULL;
}

static void
on_invocation_gone (gpointer unused,
                    GObject *where_the_object_was)
{
	g_warning ("a GDBusMethodInvocation was released but the invocation was "
	           "registered as part of a realm_invocation_lock_daemon()");
	g_assert (where_the_object_was == current_invocation);
	current_invocation = NULL;
}

gboolean
realm_invocation_lock_daemon (GDBusMethodInvocation *invocation)
{
	g_return_val_if_fail (G_IS_DBUS_METHOD_INVOCATION (invocation), FALSE);

	if (current_invocation)
		return FALSE;

	current_invocation = G_OBJECT (invocation);
	g_object_weak_ref (current_invocation, on_invocation_gone, NULL);

	/* Hold the daemon up while action */
	realm_daemon_hold ("current-invocation");

	return TRUE;
}

void
realm_invocation_unlock_daemon (GDBusMethodInvocation *invocation)
{
	g_return_if_fail (G_IS_DBUS_METHOD_INVOCATION (invocation));

	if (current_invocation != G_OBJECT (invocation)) {
		g_warning ("trying to realm_invocation_unlock_daemon() with an invocation "
		           "that is not registered as the current locked action.");
		return;
	}

	g_object_weak_unref (current_invocation, on_invocation_gone, NULL);
	current_invocation = NULL;

	/* Matches the hold in realm_invocation_lock_daemon() */
	if (!realm_daemon_release ("current-invocation"))
		g_warn_if_reached ();
}
