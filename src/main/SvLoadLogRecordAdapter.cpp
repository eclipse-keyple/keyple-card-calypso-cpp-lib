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

#include "SvLoadLogRecordAdapter.h"

/* Keyple Core Util */
#include "ByteArrayUtil.h"
#include "KeypleStd.h"
#include "System.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;

SvLoadLogRecordAdapter::SvLoadLogRecordAdapter(
  const std::vector<uint8_t>& cardResponse, const int offset)
: mOffset(offset), mCardResponse(cardResponse) {}

const std::vector<uint8_t>& SvLoadLogRecordAdapter::getRawData() const
{
    return mCardResponse;
}

int SvLoadLogRecordAdapter::getAmount() const
{
    return ByteArrayUtil::threeBytesSignedToInt(mCardResponse, mOffset + 8);
}

int SvLoadLogRecordAdapter::getBalance() const
{
    return ByteArrayUtil::threeBytesSignedToInt(mCardResponse, mOffset + 5);
}

const std::vector<uint8_t> SvLoadLogRecordAdapter::getLoadTime() const
{
    std::vector<uint8_t> loadTime(2);
    loadTime[0] = mCardResponse[mOffset + 11];
    loadTime[1] = mCardResponse[mOffset + 12];

    return loadTime;
}

const std::vector<uint8_t> SvLoadLogRecordAdapter::getLoadDate() const
{
    std::vector<uint8_t> loadDate(2);
    loadDate[0] = mCardResponse[mOffset + 0];
    loadDate[1] = mCardResponse[mOffset + 1];

    return loadDate;
}

const std::vector<uint8_t> SvLoadLogRecordAdapter::getFreeData() const
{
    std::vector<uint8_t> freeData(2);
    freeData[0] = mCardResponse[mOffset + 2];
    freeData[1] = mCardResponse[mOffset + 4];

    return freeData;
}

uint8_t SvLoadLogRecordAdapter::getKvc() const
{
    return mCardResponse[mOffset + 3];
}

const std::vector<uint8_t> SvLoadLogRecordAdapter::getSamId() const
{
    std::vector<uint8_t> samId(4);
    System::arraycopy(mCardResponse, mOffset + 13, samId, 0, 4);

    return samId;
}

int SvLoadLogRecordAdapter::getSvTNum() const
{
    std::vector<uint8_t> tnNum(2);
    tnNum[0] = mCardResponse[mOffset + 20];
    tnNum[1] = mCardResponse[mOffset + 21];

    return ByteArrayUtil::twoBytesToInt(tnNum, 0);
}

int SvLoadLogRecordAdapter::getSamTNum() const
{
    std::vector<uint8_t> samTNum(3);
    System::arraycopy(mCardResponse, mOffset + 17, samTNum, 0, 3);

    return ByteArrayUtil::threeBytesToInt(samTNum, 0);
}

std::ostream& operator<<(std::ostream& os, const SvLoadLogRecordAdapter& ra)
{
    os << "SV_LOAD_LOG_RECORD_ADAPTER: {"
       << "AMOUNT: " << ra.getAmount() << ", "
       << "BALANCE: " << ra.getBalance() << ", "
       << "DEBIT_DATE:" << ra.getLoadDate() << ", "
       << "LOAD_TIME:" << ra.getLoadDate() << ", "
       << "FREE_BYTES: " << ra.getFreeData() << ", "
       << "KVC: " << ra.getKvc() << ", "
       << "SAM_ID: " << ra.getSamId() << ", "
       << "SV_TRANSACTION_NUMBER: " << ra.getSvTNum() << ", "
       << "SV_SAM_TRANSACTION_NUMBER: " << ra.getSamTNum()
       << "}";

    return os;
}

std::ostream& operator<<(std::ostream& os, const std::shared_ptr<SvLoadLogRecordAdapter> ra)
{
    if (ra == nullptr) {
        os << "SV_LOAD_LOG_RECORD_ADAPTER: null";
    } else {
        os << *ra.get();
    }

    return os;
}

const std::string SvLoadLogRecordAdapter::toJSONString() const
{
    return "{" \
               "\"amount\":" + std::to_string(getAmount()) + ", " \
               "\"balance\":" + std::to_string(getBalance()) + ", " \
               "\"debitDate\":" + ByteArrayUtil::toHex(getLoadDate()) + ", " \
               "\"loadTime\":" + ByteArrayUtil::toHex(getLoadDate())  + ", " \
               "\"freeBytes\": \"" + ByteArrayUtil::toHex(getFreeData()) + "\", " \
               "\"kvc\":" + std::to_string(getKvc()) + ", " \
               "\"samId\": \"" + ByteArrayUtil::toHex(getSamId()) + "\", " \
               "\"svTransactionNumber\":" + std::to_string(getSvTNum()) + ", " \
               "\"svSamTransactionNumber\":" + std::to_string(getSamTNum()) + "" \
            "}";
}

}
}
}
