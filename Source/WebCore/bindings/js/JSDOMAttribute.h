/*
 *  Copyright (C) 1999-2001 Harri Porten (porten@kde.org)
 *  Copyright (C) 2003-2006, 2008-2009, 2013, 2016 Apple Inc. All rights reserved.
 *  Copyright (C) 2007 Samuel Weinig <sam@webkit.org>
 *  Copyright (C) 2009 Google, Inc. All rights reserved.
 *  Copyright (C) 2012 Ericsson AB. All rights reserved.
 *  Copyright (C) 2013 Michael Pruett <michael@68k.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#pragma once

#include "JSDOMCastedThisErrorBehavior.h"
#include "JSDOMExceptionHandling.h"

namespace WebCore {

template<typename JSClass>
class IDLAttribute {
public:
    using Setter = bool(JSC::ExecState&, JSClass&, JSC::JSValue, JSC::ThrowScope&);
    using Getter = JSC::JSValue(JSC::ExecState&, JSClass&, JSC::ThrowScope&);

    static JSClass* cast(JSC::ExecState&, JSC::EncodedJSValue);

    template<Setter setter, CastedThisErrorBehavior shouldThrow = CastedThisErrorBehavior::Throw>
    static bool set(JSC::ExecState& state, JSC::EncodedJSValue thisValue, JSC::EncodedJSValue encodedValue, const char* attributeName)
    {
        auto throwScope = DECLARE_THROW_SCOPE(state.vm());

        auto* thisObject = cast(state, thisValue);
        if (UNLIKELY(!thisObject))
            return (shouldThrow == CastedThisErrorBehavior::Throw) ? throwSetterTypeError(state, throwScope, JSClass::info()->className, attributeName) : false;

        return setter(state, *thisObject, JSC::JSValue::decode(encodedValue), throwScope);
    }

    template<Getter getter, CastedThisErrorBehavior shouldThrow = CastedThisErrorBehavior::Throw>
    static JSC::EncodedJSValue get(JSC::ExecState& state, JSC::EncodedJSValue thisValue, const char* attributeName)
    {
        auto throwScope = DECLARE_THROW_SCOPE(state.vm());

        auto* thisObject = cast(state, thisValue);
        if (UNLIKELY(!thisObject)) {
            if (shouldThrow == CastedThisErrorBehavior::Throw)
                return throwGetterTypeError(state, throwScope, JSClass::info()->className, attributeName);
            if (shouldThrow == CastedThisErrorBehavior::RejectPromise)
                return rejectPromiseWithGetterTypeError(state, JSClass::info()->className, attributeName);
            return JSC::JSValue::encode(JSC::jsUndefined());
        }

        return JSC::JSValue::encode(getter(state, *thisObject, throwScope));
    }
};

} // namespace WebCore
