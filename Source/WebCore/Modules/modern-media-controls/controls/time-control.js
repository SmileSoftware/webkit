/*
 * Copyright (C) 2016 Apple Inc. All Rights Reserved.
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

const MinimumScrubberWidthDefault = 168;
const MinimumScrubberWidthCompact = 124;
const ElapsedTimeLabelLeftMargin = -2;
const ElapsedTimeLabelWidth = 40;
const RemainingTimeLabelWidth = 49;
const AdditionalTimeLabelWidthOverAnHour = 22;
const ScrubberMargin = 5;

class TimeControl extends LayoutItem
{

    constructor(layoutDelegate)
    {
        super({
            element: `<div class="time-control"></div>`,
            layoutDelegate
        });

        this._useSixDigitsForTimeLabels = false;

        this.elapsedTimeLabel = new TimeLabel(this);
        this.scrubber = new Scrubber(layoutDelegate);
        this.remainingTimeLabel = new TimeLabel(this);

        this.children = [this.elapsedTimeLabel, this.scrubber, this.remainingTimeLabel];
    }

    // Public

    get useSixDigitsForTimeLabels()
    {
        return this._useSixDigitsForTimeLabels;
    }

    set useSixDigitsForTimeLabels(flag)
    {
        if (this._useSixDigitsForTimeLabels === flag)
            return;

        this._useSixDigitsForTimeLabels = flag;
        this.layout();
    }

    get isSufficientlyWide()
    {
        return this.scrubber.width >= ((this.layoutTraits & LayoutTraits.Compact) ? MinimumScrubberWidthCompact : MinimumScrubberWidthDefault);
    }

    // Protected

    layout()
    {
        super.layout();

        const extraWidth = this._useSixDigitsForTimeLabels ? AdditionalTimeLabelWidthOverAnHour : 0;
        const elapsedTimeLabelWidth = ElapsedTimeLabelWidth + extraWidth;
        const remainingTimeLabelWidth = RemainingTimeLabelWidth + extraWidth;

        this.elapsedTimeLabel.x = ElapsedTimeLabelLeftMargin;
        this.elapsedTimeLabel.width = elapsedTimeLabelWidth;
        this.scrubber.x = this.elapsedTimeLabel.x + elapsedTimeLabelWidth + ScrubberMargin;
        this.scrubber.width = this.width - elapsedTimeLabelWidth - ScrubberMargin - remainingTimeLabelWidth;
        this.remainingTimeLabel.x = this.scrubber.x + this.scrubber.width + ScrubberMargin;
    }

    updateScrubberLabel()
    {
        this.scrubber.inputAccessibleLabel = this.elapsedTimeLabel.value;
    }
}
