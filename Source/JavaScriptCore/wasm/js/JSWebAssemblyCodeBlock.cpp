/*
 * Copyright (C) 2017 Apple Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "JSWebAssemblyCodeBlock.h"

#if ENABLE(WEBASSEMBLY)

#include "JSCInlines.h"
#include "JSWebAssemblyLinkError.h"
#include "JSWebAssemblyMemory.h"
#include "JSWebAssemblyModule.h"
#include "WasmBinding.h"
#include "WasmModuleInformation.h"

#include <wtf/CurrentTime.h>

namespace JSC {

const ClassInfo JSWebAssemblyCodeBlock::s_info = { "WebAssemblyCodeBlock", nullptr, nullptr, nullptr, CREATE_METHOD_TABLE(JSWebAssemblyCodeBlock) };

JSWebAssemblyCodeBlock* JSWebAssemblyCodeBlock::create(VM& vm, Ref<Wasm::CodeBlock> codeBlock, JSWebAssemblyModule* module)
{
    const Wasm::ModuleInformation& moduleInformation = module->module().moduleInformation();
    auto* result = new (NotNull, allocateCell<JSWebAssemblyCodeBlock>(vm.heap, allocationSize(moduleInformation.importFunctionCount()))) JSWebAssemblyCodeBlock(vm, WTFMove(codeBlock), moduleInformation);
    result->finishCreation(vm, module);
    return result;
}

JSWebAssemblyCodeBlock::JSWebAssemblyCodeBlock(VM& vm, Ref<Wasm::CodeBlock>&& codeBlock, const Wasm::ModuleInformation& moduleInformation)
    : Base(vm, vm.webAssemblyCodeBlockStructure.get())
    , m_codeBlock(WTFMove(codeBlock))
{
    // FIXME: We should not need to do this synchronously.
    // https://bugs.webkit.org/show_bug.cgi?id=170567
    m_wasmToJSExitStubs.reserveCapacity(m_codeBlock->functionImportCount());
    for (unsigned importIndex = 0; importIndex < m_codeBlock->functionImportCount(); ++importIndex) {
        Wasm::SignatureIndex signatureIndex = moduleInformation.importFunctionSignatureIndices.at(importIndex);
        m_wasmToJSExitStubs.uncheckedAppend(Wasm::wasmToJs(&vm, m_callLinkInfos, signatureIndex, importIndex));
        importWasmToJSStub(importIndex) = m_wasmToJSExitStubs[importIndex].code().executableAddress();
    }
}

void JSWebAssemblyCodeBlock::finishCreation(VM& vm, JSWebAssemblyModule* module)
{
    Base::finishCreation(vm);
    m_module.set(vm, this, module);
}

void JSWebAssemblyCodeBlock::destroy(JSCell* cell)
{
    static_cast<JSWebAssemblyCodeBlock*>(cell)->JSWebAssemblyCodeBlock::~JSWebAssemblyCodeBlock();
}

bool JSWebAssemblyCodeBlock::isSafeToRun(JSWebAssemblyMemory* memory) const
{
    return m_codeBlock->isSafeToRun(memory->memory().mode());
}

void JSWebAssemblyCodeBlock::clearJSCallICs(VM& vm)
{
    for (auto iter = m_callLinkInfos.begin(); !!iter; ++iter)
        (*iter)->unlink(vm);
}

void JSWebAssemblyCodeBlock::visitChildren(JSCell* cell, SlotVisitor& visitor)
{
    JSWebAssemblyCodeBlock* thisObject = jsCast<JSWebAssemblyCodeBlock*>(cell);
    ASSERT_GC_OBJECT_INHERITS(thisObject, info());

    Base::visitChildren(thisObject, visitor);
    visitor.append(thisObject->m_module);

    visitor.addUnconditionalFinalizer(&thisObject->m_unconditionalFinalizer);
}

void JSWebAssemblyCodeBlock::UnconditionalFinalizer::finalizeUnconditionally()
{
    JSWebAssemblyCodeBlock* thisObject = bitwise_cast<JSWebAssemblyCodeBlock*>(
        bitwise_cast<char*>(this) - OBJECT_OFFSETOF(JSWebAssemblyCodeBlock, m_unconditionalFinalizer));
    for (auto iter = thisObject->m_callLinkInfos.begin(); !!iter; ++iter)
        (*iter)->visitWeak(*thisObject->vm());
}

} // namespace JSC

#endif // ENABLE(WEBASSEMBLY)
