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
#include <string>
#include <vector>

#include "keyple/card/calypso/CalypsoCardClass.hpp"
#include "keyple/card/calypso/CommandGetDataFci.hpp"
#include "keyple/card/calypso/ElementaryFileAdapter.hpp"
#include "keyple/card/calypso/FileHeaderAdapter.hpp"
#include "keyple/card/calypso/KeypleCardCalypsoExport.hpp"
#include "keypop/calypso/card/WriteAccessLevel.hpp"
#include "keypop/calypso/card/card/CalypsoCard.hpp"
#include "keypop/calypso/card/card/DirectoryHeader.hpp"
#include "keypop/calypso/card/card/ElementaryFile.hpp"
#include "keypop/calypso/card/card/SvDebitLogRecord.hpp"
#include "keypop/calypso/card/card/SvLoadLogRecord.hpp"
#include "keypop/calypso/crypto/asymmetric/certificate/spi/CardPublicKeySpi.hpp"
#include "keypop/card/CardSelectionResponseApi.hpp"
#include "keypop/card/spi/SmartCardSpi.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keypop::calypso::card::WriteAccessLevel;
using keypop::calypso::card::card::CalypsoCard;
using keypop::calypso::card::card::DirectoryHeader;
using keypop::calypso::card::card::ElementaryFile;
using keypop::calypso::card::card::SvDebitLogRecord;
using keypop::calypso::card::card::SvLoadLogRecord;
using keypop::calypso::crypto::asymmetric::certificate::spi::CardPublicKeySpi;
using keypop::card::CardSelectionResponseApi;
using keypop::card::spi::SmartCardSpi;

/**
 * Implementation of CalypsoCard.
 *
 * @since 2.0.0
 */
class KEYPLECARDCALYPSO_API CalypsoCardAdapter
: public CalypsoCard,
  public SmartCardSpi,
  public std::enable_shared_from_this<CalypsoCardAdapter> {
public:
    /**
     * Constructor.
     *
     * <p>Does not perform any initialization: the FCI/power-on-data parsing
     * requires a shared_ptr to this object (via shared_from_this()), which is
     * not available yet during construction. Call initialize() once the
     * instance is owned by a shared_ptr.
     *
     * @since 2.0.0
     */
    CalypsoCardAdapter();

    /**
     * Post-construction initialization function
     *
     * /!\ C++ specific
     *
     * @since 2.3.3
     */
    void initialize(
        const std::shared_ptr<CardSelectionResponseApi> cardSelectionResponse);

    /**
     * Initializes or post-initializes the object with the application FCI data.
     *
     * @param cmdCardGetDataFci The command containing the parsed FCI data.
     * @throws IllegalArgumentException If the FCI is inconsistent.
     * @since 2.2.3
     */
    void initializeWithFci(
        const std::shared_ptr<CommandGetDataFci>& cmdCardGetDataFci);

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
     * Gets the full Calypso serial number including the possible validity date
     * information in the two MSB.
     *
     * <p>The serial number to be used as diversifier for key derivation.<br>
     * This is the complete number returned by the card in its response to the
     * Select command.
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
     * Gets the maximum length of data that an APDU in this card can carry.
     *
     * @return An int
     * @since 2.0.0
     */
    virtual int getPayloadCapacity() const;

    /**
     * Tells if the change counter allowed in session is established in number
     * of operations or number of bytes modified.
     *
     * <p>This varies depending on the product type of the card.
     *
     * @return True if the counter is number of bytes
     * @since 2.0.0
     */
    bool isModificationsCounterInBytes() const;

    /**
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
    std::uint8_t getApplicationSubtype() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    std::uint8_t getSoftwareIssuer() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    std::uint8_t getSoftwareVersion() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    std::uint8_t getSoftwareRevision() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    std::uint8_t getSessionModification() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    const std::vector<std::uint8_t> getTraceabilityInformation() const override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    const std::vector<std::uint8_t>& getCardPublicKey() const override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    const std::vector<std::uint8_t>& getCardCertificate() const override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    const std::vector<std::uint8_t>& getCaCertificate() const override;

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
     * {@inheritDoc}
     *
     * @since 2.1.1
     */
    int getTransactionCounter() const override;

    /**
     * Sets the transaction counter.
     *
     * @param transactionCounter The counter value.
     * @since 2.1.1
     */
    void setTransactionCounter(const int transactionCounter);

    /**
     * Sets the Stored Value data from the SV Get command
     *
     * @param svKvc The KVC value.
     * @param svGetHeader A not empty array.
     * @param svGetData A not empty array.
     * @param svBalance the current SV balance.
     * @param svLastTNum the last SV transaction number.
     * @since 2.0.0
     */
    void setSvData(
        std::uint8_t svKvc,
        const std::vector<uint8_t>& svGetHeader,
        const std::vector<uint8_t>& svGetData,
        int svBalance,
        int svLastTNum);

    /**
     * Updates the Stored Value data from the SV Get command
     *
     * @param svBalance the current SV balance.
     * @param svLastTNum the last SV transaction number.
     * @since 2.3.3
     */
    void updateSvData(int svBalance, int svLastTNum);

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
    const std::vector<std::shared_ptr<SvDebitLogRecord>>
    getSvDebitLogAllRecords() const override;

    /**
     * Sets the ratification status
     *
     * @param dfRatified true if the session was ratified.
     * @since 2.0.0
     */
    void setDfRatified(const bool dfRatified);

    /**
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
     * Sets the DF metadata.<br>
     * Updates the invalidation flag.
     *
     * @param directoryHeader the DF metadata (should be not null).
     * @return the current instance.
     * @since 2.0.0
     */
    CalypsoCard&
    setDirectoryHeader(std::unique_ptr<DirectoryHeader> directoryHeader);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::shared_ptr<ElementaryFile>
    getFileBySfi(const uint8_t sfi) const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::shared_ptr<ElementaryFile>
    getFileByLid(const uint16_t lid) const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    const std::vector<std::shared_ptr<ElementaryFile>>&
    getFiles() const override;

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
     * Sets the PIN attempts counter.<br>
     * The PIN attempt counter is interpreted to give the results of the methods
     * isPinBlocked and getPinAttemptRemaining.
     *
     * @param pinAttemptCounter the number of remaining attempts to present the
     * PIN code.
     * @since 2.0.0
     */
    void setPinAttemptRemaining(const int pinAttemptCounter);

    /**
     * Sets the provided FileHeaderAdapter to the current selected file.<br>
     * If EF does not exist, then it is created.
     *
     * @param sfi the SFI.
     * @param header the file header (should be not null).
     * @since 2.0.0
     */
    void
    setFileHeader(std::uint8_t sfi, std::shared_ptr<FileHeaderAdapter> header);

    /**
     * Set or replace the entire content of the specified record #numRecord of
     * the current selected file by the provided content.<br>
     * If EF does not exist, then it is created.
     *
     * @param sfi the SFI.
     * @param numRecord the record number (should be {@code >=} 1).
     * @param content the content (should be not empty).
     * @since 2.0.0
     */
    void setContent(
        std::uint8_t sfi,
        std::uint8_t numRecord,
        const std::vector<uint8_t>& content);

    /**
     * Sets a counter value in record #1 of the current selected file.<br>
     * If EF does not exist, then it is created.
     *
     * @param sfi the SFI.
     * @param numCounter the counter number (should be {@code >=} 1).
     * @param content the counter value (should be not null and 3 bytes length).
     * @since 2.0.0
     */
    void setCounter(
        std::uint8_t sfi,
        std::uint8_t numCounter,
        const std::vector<uint8_t>& content);

    /**
     * Set or replace the content at the specified offset of record numRecord of
     * the current selected file by a copy of the provided content.<br>
     * If EF does not exist, then it is created.<br>
     * If actual record content is not set or has a size {@code <} offset, then
     * missing data will be padded with 0.
     *
     * @param sfi the SFI.
     * @param numRecord the record number (should be {@code >=} 1).
     * @param content the content (should be not empty).
     * @param offset the offset (should be {@code >=} 0).
     * @since 2.0.0
     */
    void setContent(
        std::uint8_t sfi,
        std::uint8_t numRecord,
        const std::vector<uint8_t>& content,
        int offset);

    /**
     * Fills the content at the specified offset of the specified record of th
     * current selected file using a binary OR operation with the provided
     * content.<br>
     * If EF does not exist, then it is created.<br>
     * If actual record content is not set or has a size {@code <} offset +
     * content size, then missing data will be completed by the provided
     * content.
     *
     * @param sfi the SFI.
     * @param numRecord the record number (should be {@code >=} 1).
     * @param content the content (should be not empty).
     * @param offset the offset (should be {@code >=} 0).
     * @since 2.1.0
     */
    void fillContent(
        std::uint8_t sfi,
        std::uint8_t numRecord,
        const std::vector<uint8_t>& content,
        int offset);

    /**
     * Add cyclic content at record #1 by rolling previously all actual records
     * contents (record #1 -> record #2, record #2 -> record #3,...) of the
     * current selected file.<br>
     * This is useful for cyclic files. Note that records are infinitely
     * shifted.<br>
     * <br>
     * If EF does not exist, then it is created.
     *
     * @param sfi the SFI.
     * @param content the content (should be not empty).
     * @since 2.0.0
     */
    void
    addCyclicContent(std::uint8_t sfi, const std::vector<uint8_t>& content);

    /**
     * Make a backup of the Elementary Files.<br>
     * This method should be used before starting a card secure session.
     *
     * @since 2.0.0
     */
    void backupFiles();

    /**
     * (package-private)<br>
     * Restore the last backup of Elementary Files.<br>
     * This method should be used when SW of the card close secure session
     * command is unsuccessful or if secure session is aborted.
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
    std::vector<std::uint8_t> getSelectApplicationResponse() const override;

    /**
     * Sets the DF invalidation status.
     *
     * @param isInvalidated true if DF is invalidated, false if DF is
     * rehabilitated.
     * @since 2.3.7
     */
    void setDfInvalidated(bool isInvalidated);

    /**
     * Sets the challenge received in response to the GET CHALLENGE command.
     *
     * @param challenge A not empty array.
     * @since 2.0.0
     */
    void setChallenge(const std::vector<uint8_t>& challenge);

    /**
     * Sets the traceability information received in response to the GET DATA
     * command for the tag GetDataTag::TRACEABILITY_INFORMATION.
     *
     * @param traceabilityInformation The traceability information.
     * @since 2.1.0
     */
    void setTraceabilityInformation(
        const std::vector<uint8_t>& traceabilityInformation);

    /**
     * Sets the card public key received in response to the GET DATA command for
     * the tag keypop::calypso::card::GetDataTag::CARD_PUBLIC_KEY.
     *
     * @param cardPublicKey The card public key.
     * @since 3.1.0
     */
    void setCardPublicKey(const std::vector<std::uint8_t>& cardPublicKey);

    /**
     * Sets the card public key retrieved from the card certificate.
     *
     * @param cardPublicKeySpi The card public key SPI.
     * @since 3.1.0
     */
    void
    setCardPublicKeySpi(std::shared_ptr<CardPublicKeySpi> cardPublicKeySpi);

    /**
     * Retrieves the card public key SPI retrieved from the card certificate.
     *
     * <p>Note that the card public key obtained with a Get Data command will
     * not be available with
     * this method.
     *
     * @return The card public key SPI or null if not available.
     * @since 3.1.0
     */
    std::shared_ptr<CardPublicKeySpi> getCardPublicKeySpi() const;

    /**
     * Adds the card certificate bytes received in response to the GET DATA
     * command for the tag keypop::calypso::card::GetDataTag::CARD_CERTIFICATE.
     *
     * @param cardCertificateBytes The card certificate bytes.
     * @param isFirstPart true when the provided data is the first part of the
     * certificate.
     * @throw IllegalArgumentException if the provided data is not a valid card
     * certificate.
     * @since 3.1.0
     */
    void addCardCertificateBytes(
        const std::vector<std::uint8_t>& cardCertificateBytes,
        bool isFirstPart);

    /**
     * Sets the CA certificate bytes received in response to the GET DATA
     * command for the tag keypop::calypso::card::GetDataTag::CA_CERTIFICATE.
     *
     * @param caCertificateBytes The CA certificate bytes.
     * @param isFirstPart true when the provided data is the first part of the
     * certificate.
     * @throw IllegalArgumentException if the provided data is not a valid CA
     * certificate.
     * @since 3.1.0
     */
    void addCaCertificateBytes(
        const std::vector<std::uint8_t>& caCertificateBytes, bool isFirstPart);

    /**
     * (package-private)<br>
     * Sets the SV signature.
     *
     * @param svOperationSignature A not empty array.
     * @since 2.0.0
     */
    void
    setSvOperationSignature(const std::vector<uint8_t>& svOperationSignature);

    /**
     * Gets the challenge received from the card
     *
     * @return An array of bytes containing the challenge bytes (variable length
     * according to the product type of the card). May be null if the challenge
     * is not available.
     * @since 2.0.0
     */
    const std::vector<uint8_t>& getChallenge() const;

    /**
     * Gets the SV KVC from the card
     *
     * @return The SV KVC byte.
     * @since 2.0.0
     */
    uint8_t getSvKvc() const;

    /**
     * Gets the SV Get command header
     *
     * @return A byte array containing the SV Get command header.
     * @throws IllegalStateException If the requested data has not been set.
     * @since 2.0.0
     */
    const std::vector<uint8_t>& getSvGetHeader() const;

    /**
     * Gets the SV Get command response data
     *
     * @return A byte array containing the SV Get command response data.
     * @throws IllegalStateException If the requested data has not been set.
     * @since 2.0.0
     */
    const std::vector<uint8_t>& getSvGetData() const;

    /**
     * Gets the last SV Operation signature (SV Reload, Debit, or Undebit)
     *
     * @return A byte array containing the SV Operation signature or null if not
     * available.
     * @since 2.0.0
     */
    const std::vector<uint8_t>& getSvOperationSignature() const;

    /**
     * Sets whether the counter-value update is postponed.
     *
     * @param isCounterValuePostponed a boolean value indicating if the
     * counter-value update should be postponed/
     * @since 3.2.1
     */
    void setIsCounterValuePostponed(bool isCounterValuePostponed);

    /**
     * Indicates if the response of the Increase/Decrease counter-command is
     * postponed to the close secure session (old revision 2 cards).
     *
     * @return true/false if the response of the Increase/Decrease
     * counter-command is postponed or not, and null if the flag is not already
     * determined.
     * @since 2.2.4
     */
    std::shared_ptr<bool> getIsCounterValuePostponed() const;

    /**
     * Indicates if the card is of a type corresponding to the specific case 1.
     *
     * @return true if the card corresponds to the specific case 1, false
     * otherwise.
     * @see #patchesRev12
     * @since 2.3.5
     */
    bool isLegacyCase1() const;

    /**
     * Disables extended mode. Although the card is in revision 3.2, it has
     * indicated in response to the "Open Secure Session" command that it does
     * not use AES keys.
     *
     * @since 2.3.1
     */
    void disableExtendedMode();

    /** */
    WriteAccessLevel getPreOpenWriteAccessLevel() const;

    /** */
    CalypsoCardAdapter&
    setPreOpenWriteAccessLevel(WriteAccessLevel preOpenWriteAccessLevel);

    /** */
    const std::vector<std::uint8_t>& getPreOpenDataOut() const;

    /** */
    CalypsoCardAdapter&
    setPreOpenDataOut(const std::vector<std::uint8_t>& preOpenDataOut);

    /** */
    friend KEYPLECARDCALYPSO_API std::ostream&
    operator<<(std::ostream& os, const CalypsoCardAdapter& cca);

    /** */
    friend KEYPLECARDCALYPSO_API std::ostream&
    operator<<(std::ostream& os, const std::shared_ptr<CalypsoCardAdapter> cca);

private:
    /**
     * POJO containing card specificities to be applied according to startup
     * info.
     */
    class Patch {
    public:
        /**
         *
         */
        friend class CalypsoCardAdapter;

        /**
         *
         */
        virtual void apply(std::shared_ptr<CalypsoCardAdapter> calypsoCard) = 0;

    private:
        /**
         *
         */
        const uint64_t mStartupInfo;

        /**
         *
         */
        const uint64_t mMask = ~0;

        /**
         *
         */
        Patch(const std::string& startupInfo, const std::string& mask);

        /**
         *
         */
        bool isApplicableTo(const uint64_t startupInfo) const;
    };

    /**
     * POJO containing card rev 3 specificities to be applied according to
     * startup info.
     */
    class PatchRev3 : public Patch {
    public:
        /**
         *
         */
        friend class CalypsoCardAdapter;

        /**
         *
         */
        virtual ~PatchRev3() = default;

        /**
         *
         */
        void apply(std::shared_ptr<CalypsoCardAdapter> calypsoCard) override;

    private:
        /**
         *
         */
        std::shared_ptr<int> mPayloadCapacity;

        /**
         *
         */
        PatchRev3(const std::string& startupInfo, const std::string& mask);

        /**
         *
         */
        PatchRev3& setPayloadCapacity(const int payloadCapacity);
    };

    /**
     * POJO containing card rev 1 & 2 specificities to be applied according to
     * startup info.
     */
    class PatchRev12 : public Patch {
    public:
        /** */
        friend class CalypsoCardAdapter;

        /** */
        virtual ~PatchRev12() = default;

        /** */
        void apply(std::shared_ptr<CalypsoCardAdapter> calypsoCard) override;

    private:
        /** */
        std::shared_ptr<bool> mIsCounterValuePostponed;

        /** */
        std::shared_ptr<bool> mIsLegacyCase1;

        /** */
        PatchRev12(const std::string& startupInfo, const std::string& mask);

        /** */
        PatchRev12& setLegacyCase1();
    };

    /** */
    const std::unique_ptr<Logger> mLogger
        = LoggerFactory::getLogger(typeid(CalypsoCardAdapter));

    /** */
    static const int CARD_REV1_ATR_LENGTH;
    static const int
        REV1_CARD_DEFAULT_WRITE_OPERATIONS_NUMBER_SUPPORTED_PER_SESSION;
    static const int
        REV2_CARD_DEFAULT_WRITE_OPERATIONS_NUMBER_SUPPORTED_PER_SESSION;
    static const int SI_BUFFER_SIZE_INDICATOR;
    static const int SI_PLATFORM;
    static const int SI_APPLICATION_TYPE;
    static const int SI_APPLICATION_SUBTYPE;
    static const int SI_SOFTWARE_ISSUER;
    static const int SI_SOFTWARE_VERSION;
    static const int SI_SOFTWARE_REVISION;
    static const int DEFAULT_PAYLOAD_CAPACITY;

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

    /** */
    std::shared_ptr<ApduResponseApi> mSelectApplicationResponse;

    /** */
    std::string mPowerOnData;

    /** */
    bool mIsExtendedModeSupported = false;

    /** */
    bool mIsRatificationOnDeselectSupported = false;

    /** */
    bool mIsSvFeatureAvailable = false;

    /** */
    bool mIsPinFeatureAvailable = false;

    /** */
    bool mIsPkiModeSupported = false;

    /** */
    bool mIsDfInvalidated = false;

    /** */
    CalypsoCardClass mCalypsoCardClass = CalypsoCardClass::UNKNOWN;

    /** */
    std::vector<uint8_t> mCalypsoSerialNumber;

    /** */
    std::vector<uint8_t> mStartupInfo;

    /** */
    CalypsoCard::ProductType mProductType = ProductType::UNKNOWN;

    /** */
    std::vector<uint8_t> mDfName;

    /** */
    int mModificationsCounterMax = 0;

    /** */
    bool mIsModificationCounterInBytes = true;

    /** */
    std::shared_ptr<DirectoryHeader> mDirectoryHeader;

    /** */
    std::vector<std::shared_ptr<ElementaryFile>> mFiles;

    /** */
    std::vector<std::shared_ptr<ElementaryFile>> mFilesBackup;

    /** */
    std::shared_ptr<ElementaryFileAdapter> mCurrentEf;

    /** */
    std::shared_ptr<bool> mIsDfRatified;

    /** */
    std::shared_ptr<int> mTransactionCounter = nullptr;

    /** */
    std::shared_ptr<int> mPinAttemptCounter;

    /** */
    std::shared_ptr<int> mSvBalance;

    /** */
    int mSvLastTNum = 0;

    /** */
    std::shared_ptr<int> mSvBalanceBackup;

    /** */
    int mSvLastTNumBackup = 0;

    /** */
    bool mIsHce = false;

    /** */
    std::vector<uint8_t> mChallenge;

    /** */
    std::vector<uint8_t> mTraceabilityInformation;

    /** */
    std::shared_ptr<CardPublicKeySpi> mCardPublicKeySpi;

    /** */
    std::vector<std::uint8_t> mCardPublicKey;

    /** */
    std::vector<std::uint8_t> mCardCertificate;

    /** */
    std::vector<std::uint8_t> mCaCertificate;

    /** */
    uint8_t mSvKvc = 0;

    /** */
    std::vector<uint8_t> mSvGetHeader;

    /** */
    std::vector<uint8_t> mSvGetData;

    /** */
    std::vector<uint8_t> mSvOperationSignature;

    /** */
    uint8_t mApplicationSubType = 0;

    /** */
    uint8_t mApplicationType = 0;

    /** */
    uint8_t mSessionModification = 0;

    /** */
    int mPayloadCapacity = DEFAULT_PAYLOAD_CAPACITY;

    /** */
    std::shared_ptr<bool> mIsCounterValuePostponed;

    /** */
    bool mIsLegacyCase1 = false;

    /** */
    WriteAccessLevel mPreOpenWriteAccessLevel = WriteAccessLevel::UNKOWN;

    /** */
    std::vector<std::uint8_t> mPreOpenDataOut;

    /** */
    static const std::vector<std::shared_ptr<PatchRev3>> mPatchesRev3;

    /** */
    static const std::vector<std::shared_ptr<PatchRev12>> mPatchesRev12;

    /**
     * Resolve the card product type from the application type byte
     *
     * @param applicationType The application type (field of startup info).
     * @return The product type.
     */
    CalypsoCard::ProductType
    computeProductType(const int applicationType) const;

    /**
     * Returns a reference to the currently selected EF.<br>
     * If the file having the provided non-zero SFI or LID does not exist, then
     * a new EF is created. <br> If the SFI and LID are both equal to 0, then
     * the previously selected EF is returned.
     *
     * @param sfi The SFI (0 if not specified in the current command).
     * @param lid The LID (0 if not specified in the current command).
     * @return a not null reference.
     */
    const std::shared_ptr<ElementaryFileAdapter>
    getOrCreateFile(const uint8_t sfi, const uint16_t lid);

    /**
     * Copy a set of ElementaryFile to another one by cloning each element.
     *
     * @param src the source (should be not null).
     * @param dest the destination (should be not null).
     */
    static void copyFiles(
        const std::vector<std::shared_ptr<ElementaryFile>>& src,
        std::vector<std::shared_ptr<ElementaryFile>>& dest);

    /**
     * Initializes the object with the card power-on data.
     *
     * <p>This method should be invoked only when no response to select
     * application is available.
     *
     * @param powerOnData The card's power-on data.
     * @throw IllegalArgumentException If powerOnData is inconsistent.
     * @since 2.0.0
     */
    void initializeWithPowerOnData(const std::string& powerOnData);

    /**
     * Initializes or post-initializes the object with the application FCI data.
     *
     * @param selectApplicationResponse The select application response.
     * @throw IllegalArgumentException If the FCI is inconsistent.
     * @since 2.0.0
     */
    void initializeWithFci(
        const std::shared_ptr<ApduResponseApi> selectApplicationResponse);

    /** */
    static const std::vector<std::shared_ptr<PatchRev12>> initPatchRev12();

    /** */
    static const std::vector<std::shared_ptr<PatchRev3>> initPatchRev3();

    /**
     * Some cards have specific features that need to be taken into account.
     * This method identifies them and applies the necessary modifications.
     */
    void applyPatchIfNeeded();

    /** */
    void applyPatchIfNeededForRevision(
        const std::vector<std::shared_ptr<Patch>>& patches,
        const std::uint64_t startupInfoLong);
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
