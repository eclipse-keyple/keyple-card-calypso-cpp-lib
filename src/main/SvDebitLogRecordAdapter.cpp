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

#include "SvDebitLogRecordAdapter.h"

/* Keyple Core Util */
#include "ByteArrayUtil.h"
#include "KeypleStd.h"
#include "System.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;

SvDebitLogRecordAdapter::SvDebitLogRecordAdapter(
  const std::vector<uint8_t>& cardResponse, const int offset)
: mOffset(offset), mCardResponse(cardResponse) {}

const std::vector<uint8_t>& SvDebitLogRecordAdapter::getRawData() const
{
    return mCardResponse;
}

int SvDebitLogRecordAdapter::getAmount() const
{
    return ByteArrayUtil::twoBytesSignedToInt(mCardResponse, mOffset);
}

int SvDebitLogRecordAdapter::getBalance() const
{
    return ByteArrayUtil::threeBytesSignedToInt(mCardResponse, mOffset + 14);
}

const std::vector<uint8_t> SvDebitLogRecordAdapter::getDebitTime() const
{
    std::vector<uint8_t> loadTime(2);
    loadTime[0] = mCardResponse[mOffset + 4];
    loadTime[1] = mCardResponse[mOffset + 5];

    return loadTime;
}

const std::vector<uint8_t> SvDebitLogRecordAdapter::getDebitDate() const
{
    std::vector<uint8_t> loadDate(2);
    loadDate[0] = mCardResponse[mOffset + 2];
    loadDate[1] = mCardResponse[mOffset + 3];

    return loadDate;
}

uint8_t SvDebitLogRecordAdapter::getKvc() const
{
    return mCardResponse[mOffset + 6];
}

const std::vector<uint8_t> SvDebitLogRecordAdapter::getSamId() const
{
    std::vector<uint8_t> samId(4);
    System::arraycopy(mCardResponse, mOffset + 7, samId, 0, 4);

    return samId;
}

int SvDebitLogRecordAdapter::getSvTNum() const
{
    std::vector<uint8_t> tnNum(2);
    tnNum[0] = mCardResponse[mOffset + 17];
    tnNum[1] = mCardResponse[mOffset + 18];

    return ByteArrayUtil::twoBytesToInt(tnNum, 0);
}

int SvDebitLogRecordAdapter::getSamTNum() const
{
    std::vector<uint8_t> samTNum(3);
    System::arraycopy(mCardResponse, mOffset + 11, samTNum, 0, 3);

    return ByteArrayUtil::threeBytesToInt(samTNum, 0);
}

std::ostream& operator<<(std::ostream& os, const SvDebitLogRecordAdapter& ra)
{
    os << "SV_DEBIT_LOG_RECORD_ADAPTER: {"
       << "AMOUNT: " << ra.getAmount() << ", "
       << "BALANCE: " << ra.getBalance() << ", "
       << "DEBIT_DATE:" << ra.getDebitDate() << ", "
       << "LOAD_TIME:" << ra.getDebitDate() << ", "
       << "KVC: " << ra.getKvc() << ", "
       << "SAM_ID: " << ra.getSamId() << ", "
       << "SV_TRANSACTION_NUMBER: " << ra.getSvTNum() << ", "
       << "SV_SAM_TRANSACTION_NUMBER: " << ra.getSamTNum()
       << "}";

    return os;
}

std::ostream& operator<<(std::ostream& os, const std::shared_ptr<SvDebitLogRecordAdapter> ra)
{
    if (ra == nullptr) {
        os << "SV_DEBIT_LOG_RECORD_ADAPTER: null";
    } else {
        os << *ra.get();
    }

    return os;
}

const std::string SvDebitLogRecordAdapter::toJSONString() const
{
    return "{" \
               "\"amount\":" + std::to_string(getAmount()) + ", " \
               "\"balance\":" + std::to_string(getBalance()) + ", " \
               "\"debitDate\":" + ByteArrayUtil::toHex(getDebitDate()) + ", " \
               "\"loadTime\":" + ByteArrayUtil::toHex(getDebitDate())  + ", " \
               "\"kvc\":" + std::to_string(getKvc()) + ", " \
               "\"samId\": \"" + ByteArrayUtil::toHex(getSamId()) + "\", " \
               "\"svTransactionNumber\":" + std::to_string(getSvTNum()) + ", " \
               "\"svSamTransactionNumber\":" + std::to_string(getSamTNum()) + "" \
            "}";
}

}
}
}
