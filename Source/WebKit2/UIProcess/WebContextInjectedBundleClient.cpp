/*
 * Copyright (C) 2010 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "WebContextInjectedBundleClient.h"

#include "WKAPICast.h"
#include "WebProcessPool.h"
#include <wtf/text/WTFString.h>

using namespace WebCore;

namespace WebKit {

void WebContextInjectedBundleClient::didReceiveMessageFromInjectedBundle(WebProcessPool* processPool, const String& messageName, API::Object* messageBody)
{
    if (!m_client.didReceiveMessageFromInjectedBundle)
        return;

    m_client.didReceiveMessageFromInjectedBundle(toAPI(processPool), toAPI(messageName.impl()), toAPI(messageBody), m_client.base.clientInfo);
}

void WebContextInjectedBundleClient::didReceiveSynchronousMessageFromInjectedBundle(WebProcessPool* processPool, const String& messageName, API::Object* messageBody, RefPtr<API::Object>& returnData)
{
    if (!m_client.didReceiveSynchronousMessageFromInjectedBundle)
        return;

    WKTypeRef returnDataRef = 0;
    m_client.didReceiveSynchronousMessageFromInjectedBundle(toAPI(processPool), toAPI(messageName.impl()), toAPI(messageBody), &returnDataRef, m_client.base.clientInfo);
    returnData = adoptRef(toImpl(returnDataRef));
}

RefPtr<API::Object> WebContextInjectedBundleClient::getInjectedBundleInitializationUserData(WebProcessPool* processPool)
{
    if (!m_client.getInjectedBundleInitializationUserData)
        return nullptr;

    return adoptRef(toImpl(m_client.getInjectedBundleInitializationUserData(toAPI(processPool), m_client.base.clientInfo)));
}

} // namespace WebKit
