/*
 * Copyright (C) 2016-2017 Apple Inc. All rights reserved.
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

#pragma once

#include <wtf/PrintStream.h>

namespace JSC {

struct FreeCell {
    FreeCell* next;
};
        
// This representation of a FreeList is convenient for the MarkedAllocator.

struct FreeList {
    FreeCell* head { nullptr };
    char* payloadEnd { nullptr };
    unsigned remaining { 0 };
    unsigned originalSize { 0 };
    
    FreeList()
    {
    }
    
    static FreeList list(FreeCell* head, unsigned bytes)
    {
        FreeList result;
        result.head = head;
        result.remaining = 0;
        result.originalSize = bytes;
        return result;
    }
    
    static FreeList bump(char* payloadEnd, unsigned remaining)
    {
        FreeList result;
        result.payloadEnd = payloadEnd;
        result.remaining = remaining;
        result.originalSize = remaining;
        return result;
    }
    
    bool operator==(const FreeList& other) const
    {
        return head == other.head
            && payloadEnd == other.payloadEnd
            && remaining == other.remaining
            && originalSize == other.originalSize;
    }
    
    bool operator!=(const FreeList& other) const
    {
        return !(*this == other);
    }
    
    explicit operator bool() const
    {
        return *this != FreeList();
    }

    bool contains(const void* target) const;

    bool allocationWillFail() const { return !head && !remaining; }
    bool allocationWillSucceed() const { return !allocationWillFail(); }
    
    void dump(PrintStream&) const;
};

} // namespace JSC

