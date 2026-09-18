/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * See the NOTICE file(s) distributed with this work for additional           *
 * information regarding copyright ownership.                                 *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the Eclipse Public License 2.0 which is available at              *
 * http://www.eclipse.org/legal/epl-2.0                                       *
 *                                                                            *
 * SPDX-License-Identifier: EPL-2.0                                           *
 ******************************************************************************/

#include "keyple/card/calypso/DtoAdapters.hpp"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "keyple/core/util/ByteArrayUtil.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/cpp/KeypleStd.hpp"
#include "keyple/core/util/cpp/System.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::ByteArrayUtil;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::System;

const int DtoAdapters::ApduRequestAdapter::DEFAULT_SUCCESSFUL_CODE = 0x9000;
const int DtoAdapters::CardSelectionRequestAdapter::SW_DEFAULT_SUCCESSFUL
    = 0x9000;

DtoAdapters::ApduRequestAdapter::ApduRequestAdapter(
    const std::vector<std::uint8_t>& apdu)
: mApdu(apdu)
, mSuccessfulStatusWords({DEFAULT_SUCCESSFUL_CODE})
{
}

DtoAdapters::ApduRequestAdapter&
DtoAdapters::ApduRequestAdapter::addSuccessfulStatusWord(
    int successfulStatusWord)
{
    mSuccessfulStatusWords.push_back(successfulStatusWord);

    return *this;
}

const std::vector<int>&
DtoAdapters::ApduRequestAdapter::getSuccessfulStatusWords() const
{
    return mSuccessfulStatusWords;
}

DtoAdapters::ApduRequestAdapter&
DtoAdapters::ApduRequestAdapter::setInfo(const std::string& info)
{
    mInfo = info;

    return *this;
}

const std::string&
DtoAdapters::ApduRequestAdapter::getInfo() const
{
    return mInfo;
}

const std::vector<std::uint8_t>&
DtoAdapters::ApduRequestAdapter::getApdu() const
{
    return mApdu;
}

void
DtoAdapters::ApduRequestAdapter::setApdu(const std::vector<std::uint8_t>& apdu)
{
    mApdu = apdu;
}

std::ostream&
operator<<(std::ostream& os, const DtoAdapters::ApduRequestAdapter& ara)
{
    os << "APDU_REQUEST_ADAPTER: {"
       << "APDU = " << ara.getApdu() << ", "
       << "SUCCESSFUL_STATUS_WORDS = " << ara.getSuccessfulStatusWords() << ", "
       << "INFO = " << ara.getInfo() << "}";

    return os;
}

std::ostream&
operator<<(
    std::ostream& os,
    const std::shared_ptr<DtoAdapters::ApduRequestAdapter>& ara)
{
    if (ara == nullptr) {
        os << "APDU_REQUEST_ADAPTER: {null}";
    } else {
        os << *ara.get();
    }

    return os;
}

DtoAdapters::CardRequestAdapter::CardRequestAdapter(
    const std::vector<std::shared_ptr<ApduRequestSpi>>& apduRequests,
    bool stopOnUnsuccessfulStatusWord)
: mApduRequests(apduRequests)
, mStopOnUnsuccessfulStatusWord(stopOnUnsuccessfulStatusWord)
{
}

const std::vector<std::shared_ptr<ApduRequestSpi>>&
DtoAdapters::CardRequestAdapter::getApduRequests() const
{
    return mApduRequests;
}

bool
DtoAdapters::CardRequestAdapter::stopOnUnsuccessfulStatusWord() const
{
    return mStopOnUnsuccessfulStatusWord;
}

std::ostream&
operator<<(std::ostream& os, const DtoAdapters::CardRequestAdapter& cra)
{
    os << "CARD_REQUEST_ADAPTER: {"
       << "APDU_REQUESTS: {";

    for (const auto& apduRequest : cra.getApduRequests()) {
        os << apduRequest << ", ";
    }

    os << "}, STOP_ON_UNSUCCESSFUL_STATUS_WORD: "
       << cra.stopOnUnsuccessfulStatusWord() << "}";

    return os;
}

std::ostream&
operator<<(
    std::ostream& os,
    const std::shared_ptr<DtoAdapters::CardRequestAdapter>& cra)
{
    if (cra == nullptr) {
        os << "CARD_REQUEST_ADAPTER: {null}";
    } else {
        os << *cra.get();
    }

    return os;
}

DtoAdapters::CardSelectionRequestAdapter::CardSelectionRequestAdapter(
    std::unique_ptr<CardRequestSpi> cardRequest)
: mCardRequest(std::move(cardRequest))
, mSuccessfulSelectionStatusWords({SW_DEFAULT_SUCCESSFUL})
{
}

void
DtoAdapters::CardSelectionRequestAdapter::addSuccessfulSelectionStatusWord(
    int successfulStatusWord)
{
    mSuccessfulSelectionStatusWords.push_back(successfulStatusWord);
}

const std::vector<int>&
DtoAdapters::CardSelectionRequestAdapter::getSuccessfulSelectionStatusWords()
    const
{
    return mSuccessfulSelectionStatusWords;
}

const std::shared_ptr<CardRequestSpi>
DtoAdapters::CardSelectionRequestAdapter::getCardRequest() const
{
    return mCardRequest;
}

std::ostream&
operator<<(
    std::ostream& os, const DtoAdapters::CardSelectionRequestAdapter& csra)
{
    os << "CARD_SELECTION_REQUEST_ADAPTER: {"
       << "CARD_REQUEST: " << csra.getCardRequest() << ", "
       << "SUCCESSFUL_SELECTION_STATUS_WORDS: "
       << csra.getSuccessfulSelectionStatusWords() << "}";

    return os;
}

std::ostream&
operator<<(
    std::ostream& os,
    const std::shared_ptr<DtoAdapters::CardSelectionRequestAdapter>& csra)
{
    if (csra == nullptr) {
        os << "CARD_SELECTION_REQUEST_ADAPTER: {null}";
    } else {
        os << *csra.get();
    }

    return os;
}

DtoAdapters::SearchCommandDataAdapter::SearchCommandDataAdapter()
: SearchCommandData()
, mSfi(1)
, mRecordNumber(1)
, mOffset(0)
, mEnableRepeatedOffset(false)
{
}

SearchCommandData&
DtoAdapters::SearchCommandDataAdapter::setSfi(std::uint8_t sfi)
{
    mSfi = sfi;

    return *this;
}

SearchCommandData&
DtoAdapters::SearchCommandDataAdapter::startAtRecord(int recordNumber)
{
    mRecordNumber = recordNumber;

    return *this;
}

SearchCommandData&
DtoAdapters::SearchCommandDataAdapter::setOffset(int offset)
{
    mOffset = offset;

    return *this;
}

SearchCommandData&
DtoAdapters::SearchCommandDataAdapter::enableRepeatedOffset()
{
    mEnableRepeatedOffset = true;

    return *this;
}

SearchCommandData&
DtoAdapters::SearchCommandDataAdapter::setSearchData(
    const std::vector<std::uint8_t>& data)
{
    mSearchData = data;

    return *this;
}

SearchCommandData&
DtoAdapters::SearchCommandDataAdapter::setMask(
    const std::vector<std::uint8_t>& mask)
{
    mMask = mask;

    return *this;
}

SearchCommandData&
DtoAdapters::SearchCommandDataAdapter::fetchFirstMatchingResult()
{
    mFetchFirstMatchingResult = true;

    return *this;
}

std::vector<int>&
DtoAdapters::SearchCommandDataAdapter::getMatchingRecordNumbers()
{
    return mMatchingRecordNumbers;
}

std::uint8_t
DtoAdapters::SearchCommandDataAdapter::getSfi() const
{
    return mSfi;
}

int
DtoAdapters::SearchCommandDataAdapter::getRecordNumber() const
{
    return mRecordNumber;
}

int
DtoAdapters::SearchCommandDataAdapter::getOffset() const
{
    return mOffset;
}

bool
DtoAdapters::SearchCommandDataAdapter::isEnableRepeatedOffset() const
{
    return mEnableRepeatedOffset;
}

const std::vector<std::uint8_t>&
DtoAdapters::SearchCommandDataAdapter::getSearchData() const
{
    return mSearchData;
}

const std::vector<std::uint8_t>&
DtoAdapters::SearchCommandDataAdapter::getMask() const
{
    return mMask;
}

bool
DtoAdapters::SearchCommandDataAdapter::isFetchFirstMatchingResult() const
{
    return mFetchFirstMatchingResult;
}

const std::vector<std::uint8_t>&
DtoAdapters::SvCommandSecurityDataApiAdapter::getSvGetRequest() const
{
    return mSvGetRequest;
}

const std::vector<std::uint8_t>&
DtoAdapters::SvCommandSecurityDataApiAdapter::getSvGetResponse() const
{
    return mSvGetResponse;
}

const std::vector<std::uint8_t>&
DtoAdapters::SvCommandSecurityDataApiAdapter::getSvCommandPartialRequest() const
{
    return mSvCommandPartialRequest;
}

DtoAdapters::SvCommandSecurityDataApiAdapter&
DtoAdapters::SvCommandSecurityDataApiAdapter::setSerialNumber(
    const std::vector<std::uint8_t>& serialNumber)
{
    mSerialNumber = serialNumber;

    return *this;
}

DtoAdapters::SvCommandSecurityDataApiAdapter&
DtoAdapters::SvCommandSecurityDataApiAdapter::setTransactionNumber(
    const std::vector<std::uint8_t>& transactionNumber)
{
    mTransactionNumber = transactionNumber;

    return *this;
}

DtoAdapters::SvCommandSecurityDataApiAdapter&
DtoAdapters::SvCommandSecurityDataApiAdapter::setTerminalChallenge(
    const std::vector<std::uint8_t>& terminalChallenge)
{
    mTerminalChallenge = terminalChallenge;

    return *this;
}

DtoAdapters::SvCommandSecurityDataApiAdapter&
DtoAdapters::SvCommandSecurityDataApiAdapter::setTerminalSvMac(
    const std::vector<std::uint8_t>& terminalSvMac)
{
    mTerminalSvMac = terminalSvMac;

    return *this;
}

SvCommandSecurityDataApi&
DtoAdapters::SvCommandSecurityDataApiAdapter::setSvGetRequest(
    const std::vector<std::uint8_t>& svGetRequest)
{
    mSvGetRequest = svGetRequest;

    return *this;
}
SvCommandSecurityDataApi&
DtoAdapters::SvCommandSecurityDataApiAdapter::setSvGetResponse(
    const std::vector<std::uint8_t>& svGetResponse)
{
    mSvGetResponse = svGetResponse;

    return *this;
}
SvCommandSecurityDataApi&
DtoAdapters::SvCommandSecurityDataApiAdapter::setSvCommandPartialRequest(
    const std::vector<std::uint8_t>& svCommandPartialRequest)
{
    mSvCommandPartialRequest = svCommandPartialRequest;

    return *this;
}

const std::vector<std::uint8_t>&
DtoAdapters::SvCommandSecurityDataApiAdapter::getSerialNumber() const
{
    return mSerialNumber;
}

const std::vector<std::uint8_t>&
DtoAdapters::SvCommandSecurityDataApiAdapter::getTransactionNumber() const
{
    return mTransactionNumber;
}

const std::vector<std::uint8_t>&
DtoAdapters::SvCommandSecurityDataApiAdapter::getTerminalChallenge() const
{
    return mTerminalChallenge;
}

const std::vector<std::uint8_t>&
DtoAdapters::SvCommandSecurityDataApiAdapter::getTerminalSvMac() const
{
    return mTerminalSvMac;
}

DtoAdapters::SvDebitLogRecordAdapter::SvDebitLogRecordAdapter(
    const std::vector<std::uint8_t>& cardResponse, int offset)
: mOffset(offset)
, mCardResponse(cardResponse)
{
}

const std::vector<std::uint8_t>&
DtoAdapters::SvDebitLogRecordAdapter::getRawData() const
{
    return mCardResponse;
}

int
DtoAdapters::SvDebitLogRecordAdapter::getAmount() const
{
    return ByteArrayUtil::extractInt(mCardResponse, mOffset, 2, true);
}

int
DtoAdapters::SvDebitLogRecordAdapter::getBalance() const
{
    return ByteArrayUtil::extractInt(mCardResponse, mOffset + 14, 3, true);
}

std::vector<std::uint8_t>
DtoAdapters::SvDebitLogRecordAdapter::getDebitTime() const
{
    std::vector<std::uint8_t> time(2);

    time[0] = mCardResponse[mOffset + 4];
    time[1] = mCardResponse[mOffset + 5];

    return time;
}

std::vector<std::uint8_t>
DtoAdapters::SvDebitLogRecordAdapter::getDebitDate() const
{
    std::vector<std::uint8_t> date(2);

    date[0] = mCardResponse[mOffset + 2];
    date[1] = mCardResponse[mOffset + 3];

    return date;
}

std::uint8_t
DtoAdapters::SvDebitLogRecordAdapter::getKvc() const
{
    return mCardResponse[mOffset + 6];
}

std::vector<std::uint8_t>
DtoAdapters::SvDebitLogRecordAdapter::getSamId() const
{
    std::vector<std::uint8_t> samId(4);

    System::arraycopy(mCardResponse, mOffset + 7, samId, 0, 4);

    return samId;
}

int
DtoAdapters::SvDebitLogRecordAdapter::getSvTNum() const
{
    std::vector<std::uint8_t> tnNum(2);

    tnNum[0] = mCardResponse[mOffset + 17];
    tnNum[1] = mCardResponse[mOffset + 18];

    return ByteArrayUtil::extractInt(tnNum, 0, 2, false);
}

int
DtoAdapters::SvDebitLogRecordAdapter::getSamTNum() const
{
    std::vector<std::uint8_t> samTNum(3);

    System::arraycopy(mCardResponse, mOffset + 11, samTNum, 0, 3);

    return ByteArrayUtil::extractInt(samTNum, 0, 3, false);
}

std::ostream&
operator<<(std::ostream& os, const DtoAdapters::SvDebitLogRecordAdapter& sdlra)
{
    os << "SV_DEBIT_LOG_RECORD_ADAPTER: {"
       << "AMOUNT: " << sdlra.getAmount() << ", "
       << "BALANCE: " << sdlra.getBalance() << ", "
       << "DEBIT_DATE: " << HexUtil::toHex(sdlra.getDebitDate()) << ", "
       << "DEBIT_TIME: " << HexUtil::toHex(sdlra.getDebitTime()) << ", "
       << "KVC: " << HexUtil::toHex(sdlra.getKvc()) << ", "
       << "SAM_ID: " << HexUtil::toHex(sdlra.getSamId()) << ", "
       << "SV_TRANSACTION_NUMBER: " << sdlra.getSvTNum() << ", "
       << "SAM_TRANSACTION_NUMBER: " << sdlra.getSamTNum() << "}";

    return os;
}

std::ostream&
operator<<(
    std::ostream& os,
    const std::shared_ptr<DtoAdapters::SvDebitLogRecordAdapter>& sdlra)
{
    if (sdlra == nullptr) {
        os << "SV_DEBIT_LOG_RECORD_ADAPTER: {null}";
    } else {
        os << *sdlra.get();
    }

    return os;
}

DtoAdapters::SvLoadLogRecordAdapter::SvLoadLogRecordAdapter(
    const std::vector<std::uint8_t>& cardResponse, int offset)
: mOffset(offset)
, mCardResponse(cardResponse)
{
}

const std::vector<std::uint8_t>&
DtoAdapters::SvLoadLogRecordAdapter::getRawData() const
{
    return mCardResponse;
}

int
DtoAdapters::SvLoadLogRecordAdapter::getAmount() const
{
    return ByteArrayUtil::extractInt(mCardResponse, mOffset + 8, 3, true);
}

int
DtoAdapters::SvLoadLogRecordAdapter::getBalance() const
{
    return ByteArrayUtil::extractInt(mCardResponse, mOffset + 5, 3, true);
}

std::vector<std::uint8_t>
DtoAdapters::SvLoadLogRecordAdapter::getLoadTime() const
{
    std::vector<std::uint8_t> time(2);

    time[0] = mCardResponse[mOffset + 11];
    time[1] = mCardResponse[mOffset + 12];

    return time;
}

std::vector<std::uint8_t>
DtoAdapters::SvLoadLogRecordAdapter::getLoadDate() const
{
    std::vector<std::uint8_t> date(2);

    date[0] = mCardResponse[mOffset];
    date[1] = mCardResponse[mOffset + 1];

    return date;
}

std::vector<std::uint8_t>
DtoAdapters::SvLoadLogRecordAdapter::getFreeData() const
{
    std::vector<std::uint8_t> free(2);

    free[0] = mCardResponse[mOffset + 2];
    free[1] = mCardResponse[mOffset + 4];

    return free;
}

std::uint8_t
DtoAdapters::SvLoadLogRecordAdapter::getKvc() const
{
    return mCardResponse[mOffset + 3];
}

std::vector<std::uint8_t>
DtoAdapters::SvLoadLogRecordAdapter::getSamId() const
{
    std::vector<std::uint8_t> samId(4);

    System::arraycopy(mCardResponse, mOffset + 13, samId, 0, 4);

    return samId;
}

int
DtoAdapters::SvLoadLogRecordAdapter::getSvTNum() const
{
    std::vector<std::uint8_t> tnNum(2);

    tnNum[0] = mCardResponse[mOffset + 20];
    tnNum[1] = mCardResponse[mOffset + 21];

    return ByteArrayUtil::extractInt(tnNum, 0, 2, false);
}

int
DtoAdapters::SvLoadLogRecordAdapter::getSamTNum() const
{
    std::vector<std::uint8_t> samTNum(3);

    System::arraycopy(mCardResponse, mOffset + 17, samTNum, 0, 3);

    return ByteArrayUtil::extractInt(samTNum, 0, 3, false);
}

std::ostream&
operator<<(std::ostream& os, const DtoAdapters::SvLoadLogRecordAdapter& sllra)
{
    os << "SV_LOAD_LOG_RECORD_ADAPTER: {"
       << "AMOUNT: " << sllra.getAmount() << ", "
       << "BALANCE: " << sllra.getBalance() << ", "
       << "LOAD_DATE: " << HexUtil::toHex(sllra.getLoadDate()) << ", "
       << "LOAD_TIME: " << HexUtil::toHex(sllra.getLoadTime()) << ", "
       << "FREE_BYTES: " << HexUtil::toHex(sllra.getFreeData()) << ", "
       << "KVC: " << HexUtil::toHex(sllra.getKvc()) << ", "
       << "SAM_ID: " << HexUtil::toHex(sllra.getSamId()) << ", "
       << "SV_TRANSACTION_NUMBER: " << sllra.getSvTNum() << ", "
       << "SAM_TRANSACTION_NUMBER: " << sllra.getSamTNum() << "}";

    return os;
}

std::ostream&
operator<<(
    std::ostream& os,
    const std::shared_ptr<DtoAdapters::SvLoadLogRecordAdapter>& sllra)
{
    if (sllra == nullptr) {
        os << "SV_LOAD_LOG_RECORD_ADAPTER: {null}";
    } else {
        os << *sllra.get();
    }

    return os;
}

DtoAdapters::CommandContextDto::CommandContextDto(
    bool isSecureSessionOpen, bool isEncryptionActive)
: mIsSecureSessionOpen(isSecureSessionOpen)
, mIsEncryptionActive(isEncryptionActive)
{
}

bool
DtoAdapters::CommandContextDto::isSecureSessionOpen() const
{
    return mIsSecureSessionOpen;
}

bool
DtoAdapters::CommandContextDto::isEncryptionActive() const
{
    return mIsEncryptionActive;
}

DtoAdapters::TransactionContextDto::TransactionContextDto(
    std::shared_ptr<CalypsoCardAdapter> card,
    std::shared_ptr<SymmetricCryptoCardTransactionManagerSpi>
        symmetricCryptoCardTransactionManagerSpi)
: mCard(card)
, mSymmetricCryptoCardTransactionManagerSpi(
      symmetricCryptoCardTransactionManagerSpi)
, mAsymmetricCryptoCardTransactionManagerSpi(nullptr)
, mIsSecureSessionOpen(false)
{
}

DtoAdapters::TransactionContextDto::TransactionContextDto(
    std::shared_ptr<CalypsoCardAdapter> card,
    std::shared_ptr<AsymmetricCryptoCardTransactionManagerSpi>
        asymmetricCryptoCardTransactionManagerSpi)
: mCard(card)
, mSymmetricCryptoCardTransactionManagerSpi(nullptr)
, mAsymmetricCryptoCardTransactionManagerSpi(
      asymmetricCryptoCardTransactionManagerSpi)
, mIsSecureSessionOpen(false)
{
}

DtoAdapters::TransactionContextDto::TransactionContextDto(
    std::shared_ptr<CalypsoCardAdapter> card)
: mCard(card)
, mSymmetricCryptoCardTransactionManagerSpi(nullptr)
, mAsymmetricCryptoCardTransactionManagerSpi(nullptr)
, mIsSecureSessionOpen(false)
{
}

DtoAdapters::TransactionContextDto::TransactionContextDto()
: mCard(nullptr)
, mSymmetricCryptoCardTransactionManagerSpi(nullptr)
, mAsymmetricCryptoCardTransactionManagerSpi(nullptr)
, mIsSecureSessionOpen(false)
{
}

std::shared_ptr<CalypsoCardAdapter>
DtoAdapters::TransactionContextDto::getCard() const
{
    return mCard;
}

std::shared_ptr<SymmetricCryptoCardTransactionManagerSpi>
DtoAdapters::TransactionContextDto ::
    getSymmetricCryptoCardTransactionManagerSpi() const
{
    return mSymmetricCryptoCardTransactionManagerSpi;
}

std::shared_ptr<AsymmetricCryptoCardTransactionManagerSpi>
DtoAdapters::TransactionContextDto ::
    getAsymmetricCryptoCardTransactionManagerSpi() const
{
    return mAsymmetricCryptoCardTransactionManagerSpi;
}

bool
DtoAdapters::TransactionContextDto::isSecureSessionOpen() const
{
    return mIsSecureSessionOpen;
}

bool
DtoAdapters::TransactionContextDto::isPkiMode() const
{
    return mAsymmetricCryptoCardTransactionManagerSpi != nullptr;
}

void
DtoAdapters::TransactionContextDto::setCard(
    std::shared_ptr<CalypsoCardAdapter> card)
{
    mCard = card;
}

void
DtoAdapters::TransactionContextDto::setSecureSessionOpen(
    bool isSecureSessionOpen)
{
    mIsSecureSessionOpen = isSecureSessionOpen;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
