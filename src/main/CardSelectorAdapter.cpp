/**************************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/                        *
 *                                                                                                *
 * See the NOTICE file(s) distributed with this work for additional information regarding         *
 * copyright ownership.                                                                           *
 *                                                                                                *
 * This program and the accompanying materials are made available under the terms of the Eclipse  *
 * Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0                  *
 *                                                                                                *
 * SPDX-License-Identifier: EPL-2.0                                                               *
 **************************************************************************************************/

#include "CardSelectorAdapter.h"

/* Keyple Core Util */
#include "ByteArrayUtil.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;

const int CardSelectorAdapter::DEFAULT_SUCCESSFUL_CODE = 0x9000;

CardSelectorAdapter::CardSelectorAdapter()
: mFileOccurrence(FileOccurrence::FIRST),
  mFileControlInformation(FileControlInformation::FCI),
  mSuccessfulSelectionStatusWords({DEFAULT_SUCCESSFUL_CODE}) {}

CardSelectorSpi& CardSelectorAdapter::filterByCardProtocol(
    const std::string& cardProtocol)
{
    mCardProtocol = cardProtocol;

    return *this;
}

CardSelectorSpi& CardSelectorAdapter::filterByPowerOnData(const std::string& powerOnDataRegex)
{
    mPowerOnDataRegex = powerOnDataRegex;

    return *this;
}

CardSelectorSpi& CardSelectorAdapter::filterByDfName(const std::vector<uint8_t>& aid)
{
    mAid = aid;

    return *this;
}

CardSelectorSpi& CardSelectorAdapter::filterByDfName(const std::string& aid)
{
    return filterByDfName(ByteArrayUtil::fromHex(aid));
}

CardSelectorSpi& CardSelectorAdapter::setFileOccurrence(const FileOccurrence fileOccurrence)
{
    mFileOccurrence = fileOccurrence;

    return *this;
}

CardSelectorSpi& CardSelectorAdapter::setFileControlInformation(
    const FileControlInformation fileControlInformation)
{
    mFileControlInformation = fileControlInformation;

    return *this;
}

CardSelectorSpi& CardSelectorAdapter::addSuccessfulStatusWord(const int statusWord)
{
    mSuccessfulSelectionStatusWords.push_back(statusWord);

    return *this;
}

const std::string& CardSelectorAdapter::getCardProtocol() const
{
    return mCardProtocol;
}

const std::string& CardSelectorAdapter::getPowerOnDataRegex() const
{
    return mPowerOnDataRegex;
}

const std::vector<uint8_t>& CardSelectorAdapter::getAid() const
{
    return mAid;
}

FileOccurrence CardSelectorAdapter::getFileOccurrence() const
{
    return mFileOccurrence;
}

FileControlInformation CardSelectorAdapter::getFileControlInformation() const
{
    return mFileControlInformation;
}

const std::vector<int>& CardSelectorAdapter::getSuccessfulSelectionStatusWords() const
{
    return mSuccessfulSelectionStatusWords;
}

}
}
}
