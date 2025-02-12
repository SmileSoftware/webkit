/*
 * Copyright (C) 2017 Igalia S.L.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "config.h"
#include "WebKitAutomationSession.h"

#include "APIAutomationSessionClient.h"
#include "WebKitAutomationSessionPrivate.h"
#include "WebKitPrivate.h"
#include "WebKitWebView.h"
#include "WebKitWebViewBasePrivate.h"
#include <glib/gi18n-lib.h>
#include <wtf/text/CString.h>

using namespace WebKit;

/**
 * SECTION: WebKitAutomationSession
 * @Short_description: Automation Session
 * @Title: WebKitAutomationSession
 *
 * WebKitAutomationSession represents an automation session of a WebKitWebContext.
 * When a new session is requested, a WebKitAutomationSession is created and the signal
 * WebKitWebContext::automation-started is emitted with the WebKitAutomationSession as
 * argument. Then, the automation client can request the session to create a new
 * #WebKitWebView to interact with it. When this happens the signal #WebKitAutomationSession::create-web-view
 * is emitted.
 *
 * Since: 2.18
 */

enum {
    PROP_0,

    PROP_ID
};

enum {
    CREATE_WEB_VIEW,

    LAST_SIGNAL
};

struct _WebKitAutomationSessionPrivate {
    RefPtr<WebAutomationSession> session;
    CString id;
};

static guint signals[LAST_SIGNAL] = { 0, };

WEBKIT_DEFINE_TYPE(WebKitAutomationSession, webkit_automation_session, G_TYPE_OBJECT)

class AutomationSessionClient final : public API::AutomationSessionClient {
public:
    explicit AutomationSessionClient(WebKitAutomationSession* session)
        : m_session(session)
    {
    }

private:
    String sessionIdentifier() const override
    {
        return String::fromUTF8(m_session->priv->id.data());
    }

    WebPageProxy* didRequestNewWindow(WebAutomationSession&) override
    {
        WebKitWebView* webView = nullptr;
        g_signal_emit(m_session, signals[CREATE_WEB_VIEW], 0, &webView);
        if (!webView || !webkit_web_view_is_controlled_by_automation(webView))
            return nullptr;

        return webkitWebViewBaseGetPage(WEBKIT_WEB_VIEW_BASE(webView));
    }

    WebKitAutomationSession* m_session;
};

static void webkitAutomationSessionGetProperty(GObject* object, guint propID, GValue* value, GParamSpec* paramSpec)
{
    WebKitAutomationSession* session = WEBKIT_AUTOMATION_SESSION(object);

    switch (propID) {
    case PROP_ID:
        g_value_set_string(value, session->priv->id.data());
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, propID, paramSpec);
    }
}

static void webkitAutomationSessionSetProperty(GObject* object, guint propID, const GValue* value, GParamSpec* paramSpec)
{
    WebKitAutomationSession* session = WEBKIT_AUTOMATION_SESSION(object);

    switch (propID) {
    case PROP_ID:
        session->priv->id = g_value_get_string(value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, propID, paramSpec);
    }
}

static void webkitAutomationSessionConstructed(GObject* object)
{
    WebKitAutomationSession* session = WEBKIT_AUTOMATION_SESSION(object);

    G_OBJECT_CLASS(webkit_automation_session_parent_class)->constructed(object);

    session->priv->session = adoptRef(new WebAutomationSession());
    session->priv->session->setSessionIdentifier(String::fromUTF8(session->priv->id.data()));
    session->priv->session->setClient(std::make_unique<AutomationSessionClient>(session));
}

static void webkit_automation_session_class_init(WebKitAutomationSessionClass* sessionClass)
{
    GObjectClass* gObjectClass = G_OBJECT_CLASS(sessionClass);
    gObjectClass->get_property = webkitAutomationSessionGetProperty;
    gObjectClass->set_property = webkitAutomationSessionSetProperty;
    gObjectClass->constructed = webkitAutomationSessionConstructed;

    /**
     * WebKitAutomationSession:id:
     *
     * The session unique identifier.
     *
     * Since: 2.18
     */
    g_object_class_install_property(
        gObjectClass,
        PROP_ID,
        g_param_spec_string(
            "id",
            _("Identifier"),
            _("The automation session identifier"),
            nullptr,
            static_cast<GParamFlags>(WEBKIT_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY)));

    /**
     * WebKitAutomationSession::create-web-view:
     * @session: a #WebKitAutomationSession
     *
     * This signal is emitted when the automation client requests a new
     * browsing context to interact with it. The callback handler should
     * return a #WebKitWebView created with #WebKitWebView:is-controlled-by-automation
     * construct property enabled. The returned #WebKitWebView could be an existing
     * web view or a new one created and added to a new tab or window.
     *
     * Returns: (transfer none): a #WebKitWebView widget.
     *
     * Since: 2.18
     */
    signals[CREATE_WEB_VIEW] = g_signal_new(
        "create-web-view",
        G_TYPE_FROM_CLASS(sessionClass),
        G_SIGNAL_RUN_LAST,
        0,
        nullptr, nullptr,
        g_cclosure_marshal_generic,
        WEBKIT_TYPE_WEB_VIEW, 0,
        G_TYPE_NONE);
}

WebKitAutomationSession* webkitAutomationSessionCreate(const char* sessionID)
{
    return WEBKIT_AUTOMATION_SESSION(g_object_new(WEBKIT_TYPE_AUTOMATION_SESSION, "id", sessionID, nullptr));
}

WebAutomationSession& webkitAutomationSessionGetSession(WebKitAutomationSession* session)
{
    return *session->priv->session;
}

/**
 * webkit_automation_session_get_id:
 * @session: a #WebKitAutomationSession
 *
 * Get the unique identifier of a #WebKitAutomationSession
 *
 * Returns: the unique identifier of @session
 *
 * Since: 2.18
 */
const char* webkit_automation_session_get_id(WebKitAutomationSession* session)
{
    g_return_val_if_fail(WEBKIT_IS_AUTOMATION_SESSION(session), nullptr);
    return session->priv->id.data();
}
