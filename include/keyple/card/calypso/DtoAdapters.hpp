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

#pragma once

#include <memory>
#include <ostream>
#include <string>
#include <vector>

#include "keypop/calypso/card/card/SvDebitLogRecord.hpp"
#include "keypop/calypso/card/card/SvLoadLogRecord.hpp"
#include "keypop/calypso/card/transaction/SearchCommandData.hpp"
#include "keypop/calypso/crypto/asymmetric/transaction/spi/AsymmetricCryptoCardTransactionManagerSpi.hpp"
#include "keypop/calypso/crypto/symmetric/SvCommandSecurityDataApi.hpp"
#include "keypop/calypso/crypto/symmetric/spi/SymmetricCryptoCardTransactionManagerSpi.hpp"
#include "keypop/card/spi/ApduRequestSpi.hpp"
#include "keypop/card/spi/CardRequestSpi.hpp"
#include "keypop/card/spi/CardSelectionRequestSpi.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keypop::calypso::card::card::SvDebitLogRecord;
using keypop::calypso::card::card::SvLoadLogRecord;
using keypop::calypso::card::transaction::SearchCommandData;
using keypop::calypso::crypto::asymmetric::transaction::spi::
    AsymmetricCryptoCardTransactionManagerSpi;
using keypop::calypso::crypto::symmetric::SvCommandSecurityDataApi;
using keypop::calypso::crypto::symmetric::spi::
    SymmetricCryptoCardTransactionManagerSpi;
using keypop::card::spi::ApduRequestSpi;
using keypop::card::spi::CardRequestSpi;
using keypop::card::spi::CardSelectionRequestSpi;

class CalypsoCardAdapter;

class DtoAdapters final {
public:
    /**
     * This POJO contains a set of data related to an ISO-7816 APDU command.
     *
     * <ul>
     *   <li>A byte array containing the raw APDU data.
     *   <li>A flag indicating if the APDU is of type 4 (ingoing and outgoing
     * data).
     *   <li>An optional set of integers corresponding to valid status words in
     * response to this APDU.
     * </ul>
     *
     * Attaching an optional name to the request facilitates the enhancement of
     * the application logs using the toString method.
     *
     * @since 2.0.0
     */
    class ApduRequestAdapter final : public ApduRequestSpi {
    public:
        /**
         * Builds an APDU request from a raw byte buffer.
         *
         * <p>The default status words list is initialized with the standard
         * successful code 9000h.
         *
         * @param apdu The bytes of the APDU's body.
         * @since 2.0.0
         */
        explicit ApduRequestAdapter(const std::vector<std::uint8_t>& apdu);

        /**
         * Adds a status word to the list of those that should be considered
         * successful for the APDU.
         *
         * <p>Note: initially, the list contains the standard successful status
         * word {@code 9000h}.
         *
         * @param successfulStatusWord A positive int &le; {@code FFFFh}.
         * @return The object instance.
         * @since 2.0.0
         */
        ApduRequestAdapter& addSuccessfulStatusWord(int successfulStatusWord);

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        const std::vector<int>& getSuccessfulStatusWords() const override;

        /**
         * Names the APDU request.
         *
         * <p>This string is dedicated to improve the readability of logs and
         * should therefore only be invoked conditionally (e.g. when log level
         * &gt;= debug).
         *
         * @param info The request name (free text).
         * @return The object instance.
         * @since 2.0.0
         */
        ApduRequestAdapter& setInfo(const std::string& info);

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        const std::string& getInfo() const override;

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        const std::vector<std::uint8_t>& getApdu() const override;

        /**
         * Sets the APDU.
         *
         * @param apdu The APDU to set.
         * @since 2.3.2
         */
        void setApdu(const std::vector<std::uint8_t>& apdu) override;

        /** */
        friend std::ostream& operator<<(
            std::ostream& os, const DtoAdapters::ApduRequestAdapter& ara);

        /** */
        friend std::ostream& operator<<(
            std::ostream& os,
            const std::shared_ptr<DtoAdapters::ApduRequestAdapter>& ara);

    private:
        /** */
        static const int DEFAULT_SUCCESSFUL_CODE;

        /** */
        std::vector<std::uint8_t> mApdu;

        /** */
        std::vector<int> mSuccessfulStatusWords;

        /** */
        std::string mInfo;
    };

    /**
     * This POJO contains an ordered list of {@link ApduRequestSpi} and the
     associated status code
     * check policy.
     *
     * @since 2.0.0
     */
    class CardRequestAdapter final : public CardRequestSpi {
    public:
        /**
         * Builds a card request with a list of ApduRequestSpi and the flag
         * indicating the expected response checking behavior.
         *
         * <p>When the status code verification is enabled, the transmission
         * of the APDUs must be interrupted as soon as the status code of a
         * response is unexpected.
         *
         * @param apduRequests A not empty list.
         * @param stopOnUnsuccessfulStatusWord true or false.
         * @since 2.0.0
         */
        CardRequestAdapter(
            const std::vector<std::shared_ptr<ApduRequestSpi>>& apduRequests,
            bool stopOnUnsuccessfulStatusWord);

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        const std::vector<std::shared_ptr<ApduRequestSpi>>&
        getApduRequests() const override;

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        bool stopOnUnsuccessfulStatusWord() const override;

        /** */
        friend std::ostream&
        operator<<(std::ostream& os, const CardRequestAdapter& cra);

        /** */
        friend std::ostream& operator<<(
            std::ostream& os, const std::shared_ptr<CardRequestAdapter>& cra);

    private:
        /** */
        std::vector<std::shared_ptr<ApduRequestSpi>> mApduRequests;

        /** */
        bool mStopOnUnsuccessfulStatusWord;
    };

    /**
     * This POJO contains the APDU to be executed in a selection case.
     *
     * <p>A selection case is defined by a
     * keypop::reader::selection::CardSelector
     * that target a particular smart card and an optional CardRequestSpi
     * containing additional APDU commands to be sent to the card when the
     * selection is successful.
     *
     * @since 2.0.0
     */
    class CardSelectionRequestAdapter final : public CardSelectionRequestSpi {
    public:
        /**
         * Builds additional APDUs to be sent after the selection step.
         *
         * @param cardRequest The card request.
         * @since 2.0.0
         */
        explicit CardSelectionRequestAdapter(
            std::unique_ptr<CardRequestSpi> cardRequest);

        /**
         * Adds the status word to the acceptation list.
         *
         * @param successfulStatusWord The status word to add.
         * @since 3.0.0
         */
        void addSuccessfulSelectionStatusWord(int successfulStatusWord);

        /** */
        const std::vector<int>&
        getSuccessfulSelectionStatusWords() const override;

        /**
         * Gets the card request.
         *
         * @return a CardRequestSpi or null if it has not been defined
         * @since 2.0.0
         */
        const std::shared_ptr<CardRequestSpi> getCardRequest() const override;

        /** */
        friend std::ostream&
        operator<<(std::ostream& os, const CardSelectionRequestAdapter& csra);

        /** */
        friend std::ostream& operator<<(
            std::ostream& os,
            const std::shared_ptr<CardSelectionRequestAdapter>& csra);

    private:
        /** */
        static const int SW_DEFAULT_SUCCESSFUL;

        /** */
        std::shared_ptr<CardRequestSpi> mCardRequest;

        /** */
        std::vector<int> mSuccessfulSelectionStatusWords;
    };

    /**
     * Implementation of SearchCommandData.
     *
     * @since 2.1.0
     */
    class SearchCommandDataAdapter final : public SearchCommandData {
    public:
        /**
         * Constructor.
         */
        SearchCommandDataAdapter();

        /**
         * {@inheritDoc}
         *
         * @since 2.1.0
         */
        SearchCommandData& setSfi(std::uint8_t sfi) override;

        /**
         * {@inheritDoc}
         *
         * @since 2.1.0
         */
        SearchCommandData& startAtRecord(int recordNumber) override;

        /**
         * {@inheritDoc}
         *
         * @since 2.1.0
         */
        SearchCommandData& setOffset(int offset) override;

        /**
         * {@inheritDoc}
         *
         * @since 2.1.0
         */
        SearchCommandData& enableRepeatedOffset() override;

        /**
         * {@inheritDoc}
         *
         * @since 2.1.0
         */
        SearchCommandData&
        setSearchData(const std::vector<std::uint8_t>& data) override;

        /**
         * {@inheritDoc}
         *
         * @since 2.1.0
         */
        SearchCommandData&
        setMask(const std::vector<std::uint8_t>& mask) override;

        /**
         * {@inheritDoc}
         *
         * @since 2.1.0
         */
        SearchCommandData& fetchFirstMatchingResult() override;

        /**
         * {@inheritDoc}
         *
         * @since 2.1.0
         */
        std::vector<int>& getMatchingRecordNumbers() override;

        /**
         * @return A not empty array of search data. It is required to check
         * input data first.
         * @note Private in Java
         * @since 2.1.0
         */
        const std::vector<std::uint8_t>& getSearchData() const;

        /**
         * @return The provided SFI or 0 if it is not set.
         * @note Private in Java
         * @since 2.1.0
         */
        std::uint8_t getSfi() const;

        /**
         * @return True if repeated offset is enabled.
         * @note Private in Java
         * @since 2.1.0
         */
        bool isEnableRepeatedOffset() const;

        /**
         * @return True if first matching result needs to be fetched.
         * @note Private in Java
         * @since 2.1.0
         */
        bool isFetchFirstMatchingResult() const;

        /**
         * @return The provided offset or 0 if it is not set.
         * @note Private in Java
         * @since 2.1.0
         */
        int getOffset() const;

        /**
         * @return Null if the mask is not set.
         * @note Private in Java
         * @since 2.1.0
         */
        const std::vector<std::uint8_t>& getMask() const;

        /**
         * @return The provided record number or 1 if it is not set.
         * @since 2.1.0
         * @note Private in Java
         */
        int getRecordNumber() const;

    private:
        /** */
        std::uint8_t mSfi;

        /** */
        int mRecordNumber;

        /** */
        int mOffset;

        /** */
        bool mEnableRepeatedOffset;

        /** */
        std::vector<std::uint8_t> mSearchData;

        /** */
        std::vector<std::uint8_t> mMask;

        /** */
        bool mFetchFirstMatchingResult;

        /** */
        std::vector<int> mMatchingRecordNumbers;
    };

    /**
     * Adapter of {@link SvCommandSecurityDataApi}
     *
     * @since 2.3.1
     */
    class SvCommandSecurityDataApiAdapter final
    : public SvCommandSecurityDataApi {
    public:
        /**
         * {@inheritDoc}
         *
         * @since 2.3.1
         */
        const std::vector<std::uint8_t>& getSvGetRequest() const override;

        /**
         * {@inheritDoc}
         *
         * @since 2.3.1
         */
        const std::vector<std::uint8_t>& getSvGetResponse() const override;

        /**
         * {@inheritDoc}
         *
         * @since 2.3.1
         */
        const std::vector<std::uint8_t>&
        getSvCommandPartialRequest() const override;

        /**
         * {@inheritDoc}
         *
         * @since 2.3.1
         */
        SvCommandSecurityDataApiAdapter&
        setSerialNumber(const std::vector<std::uint8_t>& serialNumber) override;

        /**
         * {@inheritDoc}
         *
         * @since 2.3.1
         */
        SvCommandSecurityDataApiAdapter& setTransactionNumber(
            const std::vector<std::uint8_t>& transactionNumber) override;

        /**
         * {@inheritDoc}
         *
         * @since 2.3.1
         */
        SvCommandSecurityDataApiAdapter& setTerminalChallenge(
            const std::vector<std::uint8_t>& terminalChallenge) override;

        /**
         * {@inheritDoc}
         *
         * @since 2.3.1
         */
        SvCommandSecurityDataApiAdapter& setTerminalSvMac(
            const std::vector<std::uint8_t>& terminalSvMac) override;

        /**
         *
         */
        SvCommandSecurityDataApi&
        setSvGetRequest(const std::vector<std::uint8_t>& svGetRequest);

        /**
         *
         */
        SvCommandSecurityDataApi&
        setSvGetResponse(const std::vector<std::uint8_t>& svGetResponse);

        /**
         *
         */
        SvCommandSecurityDataApi& setSvCommandPartialRequest(
            const std::vector<std::uint8_t>& svCommandPartialRequest);

        /**
         *
         */
        const std::vector<std::uint8_t>& getSerialNumber() const;

        /**
         *
         */
        const std::vector<std::uint8_t>& getTransactionNumber() const;

        /**
         *
         */
        const std::vector<std::uint8_t>& getTerminalChallenge() const;

        /**
         *
         */
        const std::vector<std::uint8_t>& getTerminalSvMac() const;

    private:
        /**
         *
         */
        std::vector<std::uint8_t> mSvGetRequest;

        /**
         *
         */
        std::vector<std::uint8_t> mSvGetResponse;

        /**
         *
         */
        std::vector<std::uint8_t> mSvCommandPartialRequest;

        /**
         *
         */
        std::vector<std::uint8_t> mSerialNumber;

        /**
         *
         */
        std::vector<std::uint8_t> mTransactionNumber;

        /**
         *
         */
        std::vector<std::uint8_t> mTerminalChallenge;

        /**
         *
         */
        std::vector<std::uint8_t> mTerminalSvMac;
    };

    /**
     * Implementation of {@link SvDebitLogRecord}.
     *
     * @since 2.0.0
     */
    class SvDebitLogRecordAdapter final : public SvDebitLogRecord {
    public:
        /**
         * Constructor
         *
         * @param cardResponse the Sv Get or Read Record (SV Load log file)
         response data.
         * @param offset the debit log offset in the response (may change
         from a card to another).
         */
        SvDebitLogRecordAdapter(
            const std::vector<std::uint8_t>& cardResponse, int offset);

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        const std::vector<std::uint8_t>& getRawData() const override;

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        int getAmount() const override;

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        int getBalance() const override;

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        std::vector<std::uint8_t> getDebitTime() const override;

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        std::vector<std::uint8_t> getDebitDate() const override;

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        std::uint8_t getKvc() const override;

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        std::vector<std::uint8_t> getSamId() const override;

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        int getSvTNum() const override;

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        int getSamTNum() const override;

        /** */
        friend std::ostream&
        operator<<(std::ostream& os, const SvDebitLogRecordAdapter& sdlra);

        /** */
        friend std::ostream& operator<<(
            std::ostream& os,
            const std::shared_ptr<SvDebitLogRecordAdapter>& sdlra);

    private:
        /** */
        int mOffset;

        /** */
        const std::vector<std::uint8_t> mCardResponse;
    };

    /**
     * Implementation of SvLoadLogRecord.
     *
     * @since 2.0.0
     */
    class SvLoadLogRecordAdapter final : public SvLoadLogRecord {
    public:
        /**
         * Constructor
         *
         * @param cardResponse the Sv Get or Read Record (SV Debit log file)
         response data.
         * @param offset the load log offset in the response (may change from
         a card to another).
         * @since 2.0.0
         */
        SvLoadLogRecordAdapter(
            const std::vector<std::uint8_t>& cardResponse, int offset);

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        const std::vector<std::uint8_t>& getRawData() const override;

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        int getAmount() const override;

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        int getBalance() const override;

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        std::vector<std::uint8_t> getLoadTime() const override;

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        std::vector<std::uint8_t> getLoadDate() const override;

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        std::vector<std::uint8_t> getFreeData() const override;

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        std::uint8_t getKvc() const override;

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        std::vector<std::uint8_t> getSamId() const override;

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        int getSvTNum() const override;

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        int getSamTNum() const override;

        /**
         *
         * @since 2.0.0
         */
        friend std::ostream&
        operator<<(std::ostream& os, const SvLoadLogRecordAdapter& sllra);

        /**
         *
         * @since 2.0.0
         */
        friend std::ostream& operator<<(
            std::ostream& os,
            const std::shared_ptr<SvLoadLogRecordAdapter>& sllra);

    private:
        /** */
        const int mOffset;

        /** */
        const std::vector<std::uint8_t> mCardResponse;
    };

    /**
     * The local command context specific to each command.
     *
     * @since 2.3.2
     */
    class CommandContextDto final {
    public:
        /**
         * Constructor.
         *
         * @param isSecureSessionOpen Is secure session open?
         * @param isEncryptionActive Is encryption active?
         * @since 2.3.2
         */
        CommandContextDto(bool isSecureSessionOpen, bool isEncryptionActive);

        /**
         * @return True if the secure session is open.
         * @since 2.3.2
         */
        bool isSecureSessionOpen() const;

        /**
         * @return True if the encryption is active.
         * @since 2.3.2
         */
        bool isEncryptionActive() const;

    private:
        /**
         *
         */
        const bool mIsSecureSessionOpen;

        /**
         *
         */
        const bool mIsEncryptionActive;
    };

    /**
     * The global transaction context common to all commands.
     *
     * @since 2.3.2
     */
    class TransactionContextDto final {
    public:
        /**
         * Constructor for symmetric crypto operations.
         *
         * @param card The Calypso card.
         * @param symmetricCryptoCardTransactionManagerSpi The symmetric crypto
         * service SPI.
         * @since 2.3.2
         */
        TransactionContextDto(
            std::shared_ptr<CalypsoCardAdapter> card,
            std::shared_ptr<SymmetricCryptoCardTransactionManagerSpi>
                symmetricCryptoCardTransactionManagerSpi);

        /**
         * Constructor for asymmetric crypto operations.
         *
         * @param card The Calypso card.
         * @param asymmetricCryptoCardTransactionManagerSpi The asymmetric
         * crypto service SPI.
         * @since 3.1.0
         */
        TransactionContextDto(
            std::shared_ptr<CalypsoCardAdapter> card,
            std::shared_ptr<AsymmetricCryptoCardTransactionManagerSpi>
                asymmetricCryptoCardTransactionManagerSpi);

        /**
         * Constructor for operations without cryptographic processes.
         *
         * @param card The Calypso card.
         * @since 3.1.0
         */
        explicit TransactionContextDto(
            std::shared_ptr<CalypsoCardAdapter> card);

        /**
         * Constructor for operations outside an existing transaction.
         *
         * @since 3.1.0
         */
        TransactionContextDto();

        /**
         * @return The Calypso card.
         * @since 2.3.2
         */
        std::shared_ptr<CalypsoCardAdapter> getCard() const;

        /**
         * @return The symmetric crypto service or "null" if not set.
         * @since 2.3.2
         */
        std::shared_ptr<SymmetricCryptoCardTransactionManagerSpi>
        getSymmetricCryptoCardTransactionManagerSpi() const;

        /**
         * @return The asymmetric crypto service or "null" if not set.
         * @since 3.1.0
         */
        std::shared_ptr<AsymmetricCryptoCardTransactionManagerSpi>
        getAsymmetricCryptoCardTransactionManagerSpi() const;

        /**
         * @return "true" if the secure session is open.
         * @since 2.3.2
         */
        bool isSecureSessionOpen() const;

        /**
         * @return "true" if the PKI mode is active.
         * @since 3.1.0
         */
        bool isPkiMode() const;

        /**
         * Sets the Calypso card.
         *
         * @param card The Calypso card.
         * @since 3.0.0
         */
        void setCard(std::shared_ptr<CalypsoCardAdapter> card);

        /**
         * @param isSecureSessionOpen Is secure session open?
         * @since 2.3.2
         */
        void setSecureSessionOpen(bool isSecureSessionOpen);

    private:
        /**
         *
         */
        std::shared_ptr<CalypsoCardAdapter> mCard;

        /**
         *
         */
        std::shared_ptr<SymmetricCryptoCardTransactionManagerSpi>
            mSymmetricCryptoCardTransactionManagerSpi;

        /**
         *
         */
        std::shared_ptr<AsymmetricCryptoCardTransactionManagerSpi>
            mAsymmetricCryptoCardTransactionManagerSpi;

        /**
         *
         */
        bool mIsSecureSessionOpen;
    };

private:
    /**
     *
     */
    DtoAdapters() = default;
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
