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

#pragma once

#include <cstdint>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

/* Calypsonet Terminal Calypso */
#include "CalypsoCard.h"
#include "DirectoryHeader.h"
#include "ElementaryFile.h"

/* Calypsonet Terminal Card */
#include "ApduResponseApi.h"
#include "SmartCardSpi.h"

/* Keyple Card Calypso */
#include "CalypsoCardClass.h"
#include "ElementaryFileAdapter.h"

/* Keyple Core Util */
#include "LoggerFactory.h"


namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::card;
using namespace calypsonet::terminal::card;
using namespace calypsonet::terminal::card::spi;
using namespace keyple::core::util::cpp;

/**
 * (package-private)<br>
 * Implementation of CalypsoCard.
 *
 * @since 2.0.0
 */
class CalypsoCardAdapter final : public CalypsoCard, public SmartCardSpi {
public:
    /**
     * Constructor.
     *
     * @since 2.0.0
     */
    CalypsoCardAdapter();

    /**
     * (package-private)<br>
     * Initializes the object with the card power-on data.
     *
     * <p>This method should be invoked only when no response to select application is available.
     *
     * @param powerOnData The card's power-on data.
     * @throw IllegalArgumentException If powerOnData is inconsistent.
     * @since 2.0.0
     */
    void initializeWithPowerOnData(const std::string& powerOnData);

    /**
     * (package-private)<br>
     * Initializes or post-initializes the object with the application FCI data.
     *
     * @param selectApplicationResponse The select application response.
     * @throws IllegalArgumentException If the FCI is inconsistent.
     * @since 2.0.0
     */
    void initializeWithFci(const std::shared_ptr<ApduResponseApi> selectApplicationResponse);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const CalypsoCard::ProductType& getProductType() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    bool isHce() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<uint8_t>& getDfName() const override;

    /**
     * (package-private)<br>
     * Gets the full Calypso serial number including the possible validity date information in the
     * two MSB.
     *
     * <p>The serial number to be used as diversifier for key derivation.<br>
     * This is the complete number returned by the card in its response to the Select command.
     *
     * @return A byte array containing the Calypso Serial Number (8 bytes)
     * @since 2.0.0
     */
    const std::vector<uint8_t>& getCalypsoSerialNumberFull() const;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<uint8_t> getApplicationSerialNumber() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<uint8_t>& getStartupInfoRawData() const override;

    /**
     * (package-private)<br>
     * Gets the maximum length of data that an APDU in this card can carry.
     *
     * @return An int
     * @since 2.0.0
     */
    int getPayloadCapacity() const;

    /**
     * (package-private)<br>
     * Tells if the change counter allowed in session is established in number of operations or
     * number of bytes modified.
     *
     * <p>This varies depending on the product type of the card.
     *
     * @return True if the counter is number of bytes
     * @since 2.0.0
     */
    bool isModificationsCounterInBytes() const;

    /**
     * (package-private)<br>
     * Indicates the maximum number of changes allowed in session.
     *
     * <p>This number can be a number of operations or a number of commands (see
     * isModificationsCounterInBytes)
     *
     * @return The maximum number of modifications allowed
     * @since 2.0.0
     */
    int getModificationsCounter() const;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    uint8_t getPlatform() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    uint8_t getApplicationType() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    bool isExtendedModeSupported() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    bool isRatificationOnDeselectSupported() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    bool isSvFeatureAvailable() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    bool isPinFeatureAvailable() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    bool isPkiModeSupported() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    uint8_t getApplicationSubtype() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    uint8_t getSoftwareIssuer() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    uint8_t getSoftwareVersion() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    uint8_t getSoftwareRevision() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    uint8_t getSessionModification() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    const std::vector<uint8_t> getTraceabilityInformation() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    bool isDfInvalidated() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    bool isDfRatified() const override;

    /**
     * (package-private)<br>
     * Sets the Stored Value data from the SV Get command
     *
     * @param svKvc The KVC value.
     * @param svGetHeader A not empty array.
     * @param svGetData A not empty array.
     * @param svBalance the current SV balance.
     * @param svLastTNum the last SV transaction number.
     * @param svLoadLogRecord the SV load log record (may be null if not available).
     * @param svDebitLogRecord the SV debit log record (may be null if not available).
     * @since 2.0.0
     */
    void setSvData(const uint8_t svKvc,
                   const std::vector<uint8_t>& svGetHeader,
                   const std::vector<uint8_t>& svGetData,
                   const int svBalance,
                   const int svLastTNum,
                   const std::shared_ptr<SvLoadLogRecord> svLoadLogRecord,
                   const std::shared_ptr<SvDebitLogRecord> svDebitLogRecord);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    int getSvBalance() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    int getSvLastTNum() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::shared_ptr<SvLoadLogRecord> getSvLoadLogRecord() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::shared_ptr<SvDebitLogRecord> getSvDebitLogLastRecord() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<std::shared_ptr<SvDebitLogRecord>> getSvDebitLogAllRecords() const override;

    /**
     * (package-private)<br>
     * Sets the ratification status
     *
     * @param dfRatified true if the session was ratified.
     * @since 2.0.0
     */
    void setDfRatified(const bool dfRatified);

    /**
     * (package-private)<br>
     * Gets the current card class.
     *
     * @return A not null reference.
     * @since 2.0.0
     */
    CalypsoCardClass getCardClass() const;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::shared_ptr<DirectoryHeader> getDirectoryHeader() const override;

    /**
     * (package-private)<br>
     * Sets the DF metadata.<br>
     * Updates the invalidation flag.
     *
     * @param directoryHeader the DF metadata (should be not null).
     * @return the current instance.
     * @since 2.0.0
     */
    CalypsoCard& setDirectoryHeader(const std::shared_ptr<DirectoryHeader> directoryHeader);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::shared_ptr<ElementaryFile> getFileBySfi(const uint8_t sfi) const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::shared_ptr<ElementaryFile> getFileByLid(const uint16_t lid) const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     * @deprecated
     */
    const std::map<const uint8_t, const std::shared_ptr<ElementaryFile>> getAllFiles() const
        override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    const std::vector<std::shared_ptr<ElementaryFile>>& getFiles() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    bool isPinBlocked() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    int getPinAttemptRemaining() const override;

    /**
     * (package-private)<br>
     * Sets the PIN attempts counter.<br>
     * The PIN attempt counter is interpreted to give the results of the methods {@link #isPinBlocked}
     * and {@link #getPinAttemptRemaining}.
     *
     * @param pinAttemptCounter the number of remaining attempts to present the PIN code.
     * @since 2.0.0
     */
    void setPinAttemptRemaining(const int pinAttemptCounter);

    /**
     * (package-private)<br>
     * Sets the provided ileHeaderAdapter} to the current selected file.<br>
     * If EF does not exist, then it is created.
     *
     * @param sfi the SFI.
     * @param header the file header (should be not null).
     * @since 2.0.0
     */
    void setFileHeader(const uint8_t sfi, const std::shared_ptr<FileHeaderAdapter> header);

    /**
     * (package-private)<br>
     * Set or replace the entire content of the specified record #numRecord of the current selected
     * file by the provided content.<br>
     * If EF does not exist, then it is created.
     *
     * @param sfi the SFI.
     * @param numRecord the record number (should be {@code >=} 1).
     * @param content the content (should be not empty).
     * @since 2.0.0
     */
    void setContent(const uint8_t sfi, const int numRecord, const std::vector<uint8_t>& content);

    /**
     * (package-private)<br>
     * Sets a counter value in record #1 of the current selected file.<br>
     * If EF does not exist, then it is created.
     *
     * @param sfi the SFI.
     * @param numCounter the counter number (should be {@code >=} 1).
     * @param content the counter value (should be not null and 3 bytes length).
     * @since 2.0.0
     */
    void setCounter(const uint8_t sfi, const int numCounter, const std::vector<uint8_t>& content);

    /**
     * (package-private)<br>
     * Set or replace the content at the specified offset of record #numRecord of the current selected
     * file by a copy of the provided content.<br>
     * If EF does not exist, then it is created.<br>
     * If actual record content is not set or has a size {@code <} offset, then missing data will be
     * padded with 0.
     *
     * @param sfi the SFI.
     * @param numRecord the record number (should be {@code >=} 1).
     * @param content the content (should be not empty).
     * @param offset the offset (should be {@code >=} 0).
     * @since 2.0.0
     */
    void setContent(const uint8_t sfi,
                    const int numRecord,
                    const std::vector<uint8_t>& content,
                    const int offset);

    /**
     * (package-private)<br>
     * Fills the content at the specified offset of the specified record of the current selected
     * file using a binary OR operation with the provided content.<br>
     * If EF does not exist, then it is created.<br>
     * If actual record content is not set or has a size {@code <} offset + content size, then
     * missing data will be completed by the provided content.
     *
     * @param sfi the SFI.
     * @param numRecord the record number (should be {@code >=} 1).
     * @param content the content (should be not empty).
     * @since 2.1.0
     */
    void fillContent(const uint8_t sfi,
                     const int numRecord,
                     const std::vector<uint8_t>& content,
                     const int offset);

    /**
     * (package-private)<br>
     * Add cyclic content at record #1 by rolling previously all actual records contents (record
     * #1 -> record #2, record #2 -> record #3,...) of the current selected file.<br>
     * This is useful for cyclic files. Note that records are infinitely shifted.<br>
     * <br>
     * If EF does not exist, then it is created.
     *
     * @param sfi the SFI.
     * @param content the content (should be not empty).
     * @since 2.0.0
     */
    void addCyclicContent(const uint8_t sfi, const std::vector<uint8_t> content);

    /**
     * (package-private)<br>
     * Make a backup of the Elementary Files.<br>
     * This method should be used before starting a card secure session.
     *
     * @since 2.0.0
     */
    void backupFiles();

    /**
     * (package-private)<br>
     * Restore the last backup of Elementary Files.<br>
     * This method should be used when SW of the card close secure session command is unsuccessful
     * or if secure session is aborted.
     *
     * @since 2.0.0
     */
    void restoreFiles();

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::string& getPowerOnData() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<uint8_t> getSelectApplicationResponse() const override;

    /**
     * (package-private)<br>
     * Sets the challenge received in response to the GET CHALLENGE command.
     *
     * @param cardChallenge A not empty array.
     * @since 2.0.0
     */
    void setCardChallenge(const std::vector<uint8_t>& cardChallenge);

    /**
     * (package-private)<br>
     * Sets the traceability information received in response to the GET DATA command for the tag
     * GetDataTag::TRACEABILITY_INFORMATION}.
     *
     * @param traceabilityInformation The traceability information.
     * @since 2.1.0
     */
    void setTraceabilityInformation(const std::vector<uint8_t>& traceabilityInformation);

    /**
     * (package-private)<br>
     * Sets the SV signature.
     *
     * @param svOperationSignature A not empty array.
     * @since 2.0.0
     */
    void setSvOperationSignature(const std::vector<uint8_t>& svOperationSignature);

    /**
     * (package-private)<br>
     * Gets the challenge received from the card
     *
     * @return An array of bytes containing the challenge bytes (variable length according to the
     *     product type of the card). May be null if the challenge is not available.
     * @since 2.0.0
     */
    const std::vector<uint8_t>& getCardChallenge() const;

    /**
     * (package-private)<br>
     * Gets the SV KVC from the card
     *
     * @return The SV KVC byte.
     * @since 2.0.0
     */
    uint8_t getSvKvc() const;

    /**
     * (package-private)<br>
     * Gets the SV Get command header
     *
     * @return A byte array containing the SV Get command header.
     * @throws IllegalStateException If the requested data has not been set.
     * @since 2.0.0
     */
    const std::vector<uint8_t>& getSvGetHeader() const;

    /**
     * (package-private)<br>
     * Gets the SV Get command response data
     *
     * @return A byte array containing the SV Get command response data.
     * @throws IllegalStateException If the requested data has not been set.
     * @since 2.0.0
     */
    const std::vector<uint8_t>& getSvGetData() const;

    /**
     * (package-private)<br>
     * Gets the last SV Operation signature (SV Reload, Debit or Undebit)
     *
     * @return A byte array containing the SV Operation signature or null if not available.
     * @since 2.0.0
     */
    const std::vector<uint8_t>& getSvOperationSignature() const;

    /**
     *
     */
    friend std::ostream& operator<<(std::ostream& os, const CalypsoCardAdapter& cca);

    /**
     *
     */
    friend std::ostream& operator<<(std::ostream& os,
                                    const std::shared_ptr<CalypsoCardAdapter> cca);

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger = LoggerFactory::getLogger(typeid(CalypsoCardAdapter));

    /**
     *
     */
    static const std::string PATTERN_1_BYTE_HEX;
    static const std::string PATTERN_2_BYTES_HEX;

    /**
     *
     */
    static const int CARD_REV1_ATR_LENGTH;
    static const int REV1_CARD_DEFAULT_WRITE_OPERATIONS_NUMBER_SUPPORTED_PER_SESSION;
    static const int REV2_CARD_DEFAULT_WRITE_OPERATIONS_NUMBER_SUPPORTED_PER_SESSION;
    static const int SI_BUFFER_SIZE_INDICATOR;
    static const int SI_PLATFORM;
    static const int SI_APPLICATION_TYPE;
    static const int SI_APPLICATION_SUBTYPE;
    static const int SI_SOFTWARE_ISSUER;
    static const int SI_SOFTWARE_VERSION;
    static const int SI_SOFTWARE_REVISION;
    static const int PAY_LOAD_CAPACITY;

    /**
     * Application type bitmasks features
     */
    static const uint8_t APP_TYPE_WITH_CALYPSO_PIN;
    static const uint8_t APP_TYPE_WITH_CALYPSO_SV;
    static const uint8_t APP_TYPE_RATIFICATION_COMMAND_REQUIRED;
    static const uint8_t APP_TYPE_CALYPSO_REV_32_MODE;
    static const uint8_t APP_TYPE_WITH_PUBLIC_AUTHENTICATION;

    /**
     * Buffer indicator to buffer size lookup table
     */
    static const std::vector<int> BUFFER_SIZE_INDICATOR_TO_BUFFER_SIZE;

    /**
     *
     */
    std::shared_ptr<ApduResponseApi> mSelectApplicationResponse;

    /**
     *
     */
    std::string mPowerOnData;

    /**
     *
     */
    bool mIsExtendedModeSupported;

    /**
     *
     */
    bool mIsRatificationOnDeselectSupported;

    /**
     *
     */
    bool mIsSvFeatureAvailable;

    /**
     *
     */
    bool mIsPinFeatureAvailable;

    /**
     *
     */
    bool mIsPkiModeSupported;

    /**
     *
     */
    bool mIsDfInvalidated;

    /**
     *
     */
    CalypsoCardClass mCalypsoCardClass;

    /**
     *
     */
    std::vector<uint8_t> mCalypsoSerialNumber;

    /**
     *
     */
    std::vector<uint8_t> mStartupInfo;

    /**
     *
     */
    CalypsoCard::ProductType mProductType;

    /**
     *
     */
    std::vector<uint8_t> mDfName;

    /**
     *
     */
    int mModificationsCounterMax;

    /**
     *
     */
    bool mIsModificationCounterInBytes;

    /**
     *
     */
    std::shared_ptr<DirectoryHeader> mDirectoryHeader;

    /**
     *
     */
    std::vector<std::shared_ptr<ElementaryFile>> mFiles;

    /**
     *
     */
    std::vector<std::shared_ptr<ElementaryFile>> mFilesBackup;

    /**
     *
     */
    uint8_t mCurrentSfi;

    /**
     *
     */
    uint16_t mCurrentLid;

    /**
     *
     */
    std::shared_ptr<bool> mIsDfRatified;

    /**
     *
     */
    std::shared_ptr<int> mPinAttemptCounter;

    /**
     *
     */
    std::shared_ptr<int> mSvBalance;

    /**
     *
     */
    int mSvLastTNum;

    /**
     *
     */
    std::shared_ptr<SvLoadLogRecord> mSvLoadLogRecord;

    /**
     *
     */
    std::shared_ptr<SvDebitLogRecord> mSvDebitLogRecord;

    /**
     *
     */
    bool mIsHce;

    /**
     *
     */
    std::vector<uint8_t> mCardChallenge;

    /**
     *
     */
    std::vector<uint8_t> mTraceabilityInformation;

    /**
     *
     */
    uint8_t mSvKvc;

    /**
     *
     */
    std::vector<uint8_t> mSvGetHeader;

    /**
     *
     */
    std::vector<uint8_t> mSvGetData;

    /**
     *
     */
    std::vector<uint8_t> mSvOperationSignature;

    /**
     *
     */
    uint8_t mApplicationSubType;

    /**
     *
     */
    uint8_t mApplicationType;

    /**
     *
     */
    uint8_t mSessionModification;

    /**
     * Resolve the card product type from the application type byte
     *
     * @param applicationType The application type (field of startup info).
     * @return The product type.
     */
    CalypsoCard::ProductType computeProductType(const int applicationType) const;

    /**
     * (private)<br>
     * Updates the SFI information of the current selected file.
     *
     * @param sfi The SFI.
     */
    void updateCurrentSfi(const uint8_t sfi);

    /**
     * (private)<br>
     * Updates the LID information of the current selected file.
     *
     * @param lid The LID.
     */
    void updateCurrentLid(const uint16_t lid);

    /**
     * (private)<br>
     * Gets or creates the EF having the current non-zero SFI, or the current non-zero LID if the
     * SFI is 0.
     *
     * <p>The current SFI and LID cannot both be equal to 0.
     *
     * @return a not null reference.
     */
    const std::shared_ptr<ElementaryFileAdapter> getOrCreateFile();

     /**
     * (private)<br>
     * Copy a set of ElementaryFile to another one by cloning each element.
     *
     * @param src the source (should be not null).
     * @param dest the destination (should be not null).
     */
    static void copyFiles(const std::vector<std::shared_ptr<ElementaryFile>>& src,
                          std::vector<std::shared_ptr<ElementaryFile>>& dest);
};

}
}
}