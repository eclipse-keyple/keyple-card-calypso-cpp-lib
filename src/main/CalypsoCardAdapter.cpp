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

#include "CalypsoCardAdapter.h"

/* Calypsonet Terminal Calypso */
#include "FileHeader.h"

/* Keyple Core Util */
#include "ByteArrayUtil.h"
#include "IllegalArgumentException.h"
#include "IllegalStateException.h"
#include "KeypleStd.h"
#include "System.h"

/* Keyple Core Calypso */
#include "CalypsoCardConstant.h"
#include "CmdCardGetDataFci.h"
#include "SvDebitLogRecordAdapter.h"
#include "SvLoadLogRecordAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso;
using namespace keyple::core::util;
using namespace keyple::core::util::cpp;
using namespace keyple::core::util::cpp::exception;

const std::string CalypsoCardAdapter::PATTERN_1_BYTE_HEX = "%02Xh";
const std::string CalypsoCardAdapter::PATTERN_2_BYTES_HEX = "%04Xh";

const int CalypsoCardAdapter::CARD_REV1_ATR_LENGTH = 20;
const int CalypsoCardAdapter::REV1_CARD_DEFAULT_WRITE_OPERATIONS_NUMBER_SUPPORTED_PER_SESSION = 3;
const int CalypsoCardAdapter::REV2_CARD_DEFAULT_WRITE_OPERATIONS_NUMBER_SUPPORTED_PER_SESSION = 6;
const int CalypsoCardAdapter::SI_BUFFER_SIZE_INDICATOR = 0;
const int CalypsoCardAdapter::SI_PLATFORM = 1;
const int CalypsoCardAdapter::SI_APPLICATION_TYPE = 2;
const int CalypsoCardAdapter::SI_APPLICATION_SUBTYPE = 3;
const int CalypsoCardAdapter::SI_SOFTWARE_ISSUER = 4;
const int CalypsoCardAdapter::SI_SOFTWARE_VERSION = 5;
const int CalypsoCardAdapter::SI_SOFTWARE_REVISION = 6;
const int CalypsoCardAdapter::PAY_LOAD_CAPACITY = 250;

const uint8_t CalypsoCardAdapter::APP_TYPE_WITH_CALYPSO_PIN = 0x01;
const uint8_t CalypsoCardAdapter::APP_TYPE_WITH_CALYPSO_SV = 0x02;
const uint8_t CalypsoCardAdapter::APP_TYPE_RATIFICATION_COMMAND_REQUIRED = 0x04;
const uint8_t CalypsoCardAdapter::APP_TYPE_CALYPSO_REV_32_MODE = 0x08;
const uint8_t CalypsoCardAdapter::APP_TYPE_WITH_PUBLIC_AUTHENTICATION = 0x10;

const std::vector<int> CalypsoCardAdapter::BUFFER_SIZE_INDICATOR_TO_BUFFER_SIZE = {
    0, 0, 0, 0, 0, 0, 215, 256, 304, 362, 430, 512, 608, 724, 861, 1024, 1217, 1448, 1722, 2048,
    2435, 2896, 3444, 4096, 4870, 5792, 6888, 8192, 9741, 11585, 13777, 16384, 19483, 23170,
    27554, 32768, 38967, 46340, 55108, 65536, 77935, 92681, 110217, 131072, 155871, 185363,
    220435, 262144, 311743, 370727, 440871, 524288, 623487, 741455, 881743, 1048576
};

CalypsoCardAdapter::CalypsoCardAdapter()
: mCalypsoCardClass(CalypsoCardClass::UNKNOWN),
  mProductType(ProductType::UNKNOWN),
  mIsModificationCounterInBytes(true) {}

void CalypsoCardAdapter::initializeWithPowerOnData(const std::string& powerOnData)
{
    mPowerOnData = powerOnData;

    /*
     * FCI is not provided: we consider it is Calypso card rev 1, it's serial number is provided in
     * the ATR.
     */
    const std::vector<uint8_t> atr = ByteArrayUtil::fromHex(powerOnData);

    /* Basic check: we expect to be here following a selection based on the ATR */
    if (atr.size() != CARD_REV1_ATR_LENGTH) {
        throw IllegalArgumentException("Unexpected ATR length: " + powerOnData);
    }

    mDfName.empty();
    mCalypsoSerialNumber = std::vector<uint8_t>(8);

    /*
     * Old cards have their modification counter in number of commands the array is initialized with
     * 0 (cf. default value for primitive types).
     */
    System::arraycopy(atr, 12, mCalypsoSerialNumber, 4, 4);
    mModificationsCounterMax = REV1_CARD_DEFAULT_WRITE_OPERATIONS_NUMBER_SUPPORTED_PER_SESSION;

    mStartupInfo = std::vector<uint8_t>(7);

    /* Create buffer size indicator */
    mStartupInfo[0] = static_cast<uint8_t>(mModificationsCounterMax);

    /* Create the startup info with the 6 bytes of the ATR from position 6 */
    System::arraycopy(atr, 6, mStartupInfo, 1, 6);

    mIsRatificationOnDeselectSupported = true;

    mProductType = ProductType::PRIME_REVISION_1;
    mCalypsoCardClass = CalypsoCardClass::LEGACY;
}

void CalypsoCardAdapter::initializeWithFci(
    const std::shared_ptr<ApduResponseApi> selectApplicationResponse)
{
    mSelectApplicationResponse = selectApplicationResponse;

    if (selectApplicationResponse->getDataOut().size() == 0) {
        /* No FCI provided. May be filled later with a Get Data response */
        return;
    }

    /*
     * Parse card FCI - to retrieve DF Name (AID), Serial Number, &amp; StartupInfo
     * CL-SEL-TLVSTRUC.1
     */
    auto cardGetDataFci = std::make_shared<CmdCardGetDataFci>();
    const auto& cmdCardGetDataFci = cardGetDataFci->setApduResponse(selectApplicationResponse);

    if (!cmdCardGetDataFci.isValidCalypsoFCI()) {
        throw IllegalArgumentException("Bad FCI format.");
    }

    mIsDfInvalidated = cmdCardGetDataFci.isDfInvalidated();

    /* CL-SEL-DATA.1 */
    mDfName = cmdCardGetDataFci.getDfName();
    mCalypsoSerialNumber = cmdCardGetDataFci.getApplicationSerialNumber();

    /* CL-SI-OTHER.1 */
    mStartupInfo = cmdCardGetDataFci.getDiscretionaryData();

    /*
     * CL-SI-ATRFU.1
     * CL-SI-ATPRIME.1
     * CL-SI-ATB6B5.1
     * CL-SI-ATLIGHT.1
     * CL-SI-ATBASIC.1
     */
    mApplicationType = mStartupInfo[SI_APPLICATION_TYPE];
    mProductType = computeProductType(mApplicationType & 0xFF);

    /* CL-SI-ASRFU.1 */
    mApplicationSubType = mStartupInfo[SI_APPLICATION_SUBTYPE];
    if (mApplicationSubType == 0x00 || mApplicationSubType == 0xFF) {
        throw IllegalArgumentException("Unexpected application subtype: " + mApplicationSubType);
    }

    mSessionModification = mStartupInfo[SI_BUFFER_SIZE_INDICATOR];

    if (mProductType == ProductType::PRIME_REVISION_2) {
        mCalypsoCardClass = CalypsoCardClass::LEGACY;

        /* Old cards have their modification counter in number of commands */
        mIsModificationCounterInBytes = false;
        mModificationsCounterMax = REV2_CARD_DEFAULT_WRITE_OPERATIONS_NUMBER_SUPPORTED_PER_SESSION;

    } else if (mProductType == ProductType::BASIC) {
        /* CL-SI-SMBASIC.1 */
        if (mSessionModification < 0x04 || mSessionModification > 0x37) {
            throw IllegalArgumentException("Wrong session modification value for a Basic type " \
                                           "(should be between 04h and 37h): " +
                                           mSessionModification);
        }

        mCalypsoCardClass = CalypsoCardClass::ISO;
        mIsModificationCounterInBytes = false;
        mModificationsCounterMax = 3; // TODO Verify this
    } else {
        mCalypsoCardClass = CalypsoCardClass::ISO;

        /*
         * Session buffer size
         * CL-SI-SM.1
         */
        if (mSessionModification < 0x06 || mSessionModification > 0x37) {
            throw IllegalArgumentException("Session modifications byte should be in range 06h to" \
                                           " 47h. Was: " + mSessionModification);
        }

        mModificationsCounterMax = BUFFER_SIZE_INDICATOR_TO_BUFFER_SIZE[mSessionModification];
    }

    /* CL-SI-ATOPT.1 */
    if (mProductType == ProductType::PRIME_REVISION_3) {
        mIsExtendedModeSupported = (mApplicationType & APP_TYPE_CALYPSO_REV_32_MODE) != 0;
        mIsRatificationOnDeselectSupported =
            (mApplicationType & APP_TYPE_RATIFICATION_COMMAND_REQUIRED) == 0;
        mIsPkiModeSupported = (mApplicationType & APP_TYPE_WITH_PUBLIC_AUTHENTICATION) != 0;
    }

    if (mProductType == ProductType::PRIME_REVISION_3 ||
        mProductType == ProductType::PRIME_REVISION_2) {
        mIsSvFeatureAvailable = (mApplicationType & APP_TYPE_WITH_CALYPSO_SV) != 0;
        mIsPinFeatureAvailable = (mApplicationType & APP_TYPE_WITH_CALYPSO_PIN) != 0;
    }

    mIsHce = (mCalypsoSerialNumber[3] & 0x80) == 0x80;
}

CalypsoCard::ProductType CalypsoCardAdapter::computeProductType(const int applicationType) const
{
    if (applicationType == 0) {
        throw IllegalArgumentException("Invalid application type 00h");
    } else if (applicationType == 0xFF) {
        return ProductType::UNKNOWN;
    } else if (applicationType <= 0x1F) {
        return ProductType::PRIME_REVISION_2;
    } else if (applicationType >= 0x90 && applicationType <= 0x97) {
        return ProductType::LIGHT;
    } else if (applicationType >= 0x98 && applicationType <= 0x9F) {
        return ProductType::BASIC;
    }

    return ProductType::PRIME_REVISION_3;
}

const CalypsoCard::ProductType& CalypsoCardAdapter::getProductType() const
{
    return mProductType;
}

bool CalypsoCardAdapter::isHce() const
{
    return mIsHce;
}

const std::vector<uint8_t>& CalypsoCardAdapter::getDfName() const
{
    return mDfName;
}

const std::vector<uint8_t>& CalypsoCardAdapter::getCalypsoSerialNumberFull() const
{
    return mCalypsoSerialNumber;
}

const std::vector<uint8_t> CalypsoCardAdapter::getApplicationSerialNumber() const
{
    std::vector<uint8_t> applicationSerialNumber = mCalypsoSerialNumber;
    applicationSerialNumber[0] = 0;
    applicationSerialNumber[1] = 0;

    return applicationSerialNumber;
}

const std::vector<uint8_t>& CalypsoCardAdapter::getStartupInfoRawData() const
{
    return mStartupInfo;
}

int CalypsoCardAdapter::getPayloadCapacity() const
{
    // TODO make this value dependent on the type of card identified
    return PAY_LOAD_CAPACITY;
}

bool CalypsoCardAdapter::isModificationsCounterInBytes() const
{
    return mIsModificationCounterInBytes;
}

int CalypsoCardAdapter::getModificationsCounter() const
{
    return mModificationsCounterMax;
}

uint8_t CalypsoCardAdapter::getPlatform() const
{
    return mStartupInfo[SI_PLATFORM];
}

uint8_t CalypsoCardAdapter::getApplicationType() const
{
    return mApplicationType;
}

bool CalypsoCardAdapter::isExtendedModeSupported() const
{
    return mIsExtendedModeSupported;
}

bool CalypsoCardAdapter::isRatificationOnDeselectSupported() const
{
    return mIsRatificationOnDeselectSupported;
}

bool CalypsoCardAdapter::isSvFeatureAvailable() const
{
    return mIsSvFeatureAvailable;
}

bool CalypsoCardAdapter::isPinFeatureAvailable() const
{
    return mIsPinFeatureAvailable;
}

bool CalypsoCardAdapter::isPkiModeSupported() const
{
    return mIsPkiModeSupported;
}

uint8_t CalypsoCardAdapter::getApplicationSubtype() const
{
    return mApplicationSubType;
}

uint8_t CalypsoCardAdapter::getSoftwareIssuer() const
{
    return mStartupInfo[SI_SOFTWARE_ISSUER];
}

uint8_t CalypsoCardAdapter::getSoftwareVersion() const
{
    return mStartupInfo[SI_SOFTWARE_VERSION];
}

uint8_t CalypsoCardAdapter::getSoftwareRevision() const
{
    return mStartupInfo[SI_SOFTWARE_REVISION];
}

uint8_t CalypsoCardAdapter::getSessionModification() const
{
    return mSessionModification;
}

const std::vector<uint8_t> CalypsoCardAdapter::getTraceabilityInformation() const
{
    /* Java code: return traceabilityInformation != null ? traceabilityInformation : new byte[0]; */
    return mTraceabilityInformation;
}

bool CalypsoCardAdapter::isDfInvalidated() const
{
    return mIsDfInvalidated;
}

bool CalypsoCardAdapter::isDfRatified() const
{
    if (mIsDfRatified != nullptr) {
        return *mIsDfRatified.get();
    }

    throw IllegalStateException("Unable to determine the ratification status. No session was " \
                                "opened.");
}

void CalypsoCardAdapter::setSvData(const uint8_t svKvc,
                                   const std::vector<uint8_t>& svGetHeader,
                                   const std::vector<uint8_t>& svGetData,
                                   const int svBalance,
                                   const int svLastTNum,
                                   const std::shared_ptr<SvLoadLogRecord> svLoadLogRecord,
                                   const std::shared_ptr<SvDebitLogRecord> svDebitLogRecord)
{
    mSvKvc = svKvc;
    mSvGetHeader = svGetHeader;
    mSvGetData = svGetData;
    mSvBalance = std::make_shared<int>(svBalance);
    mSvLastTNum = svLastTNum;

    /* Update logs, do not overwrite existing values (case of double reading) */
    if (mSvLoadLogRecord == nullptr) {
        mSvLoadLogRecord = svLoadLogRecord;
    }

    if (mSvDebitLogRecord == nullptr) {
        mSvDebitLogRecord = svDebitLogRecord;
    }
}

int CalypsoCardAdapter::getSvBalance() const
{
    if (mSvBalance == nullptr) {
        throw IllegalStateException("No SV Get command has been executed.");
    }

    return *mSvBalance.get();
}

int CalypsoCardAdapter::getSvLastTNum() const
{
    if (mSvBalance == nullptr) {
         new IllegalStateException("No SV Get command has been executed.");
    }

    return mSvLastTNum;
}

const std::shared_ptr<SvLoadLogRecord> CalypsoCardAdapter::getSvLoadLogRecord()
{
    if (mSvLoadLogRecord == nullptr) {
        /* Try to get it from the file data */
        const std::shared_ptr<ElementaryFile> ef =
            getFileBySfi(CalypsoCardConstant::SV_RELOAD_LOG_FILE_SFI);
        if (ef != nullptr) {
            const std::vector<uint8_t> logRecord = ef->getData()->getContent();
            mSvLoadLogRecord = std::make_shared<SvLoadLogRecordAdapter>(logRecord, 0);
        }
    }

    return mSvLoadLogRecord;
}

const std::shared_ptr<SvDebitLogRecord> CalypsoCardAdapter::getSvDebitLogLastRecord()
{
    if (mSvDebitLogRecord == nullptr) {
        /* Try to get it from the file data */
        const std::vector<std::shared_ptr<SvDebitLogRecord>> svDebitLogRecords =
            getSvDebitLogAllRecords();
        mSvDebitLogRecord = svDebitLogRecords[0];
    }

    return mSvDebitLogRecord;
}

const std::vector<std::shared_ptr<SvDebitLogRecord>> CalypsoCardAdapter::getSvDebitLogAllRecords()
    const
{
    std::vector<std::shared_ptr<SvDebitLogRecord>> svDebitLogRecords;

    /* Get the logs from the file data */
    const std::shared_ptr<ElementaryFile> ef =
        getFileBySfi(CalypsoCardConstant::SV_DEBIT_LOG_FILE_SFI);
    if (ef == nullptr) {
        return svDebitLogRecords;
    }

    const std::map<int, std::vector<uint8_t>>& logRecords = ef->getData()->getAllRecordsContent();
    for (const auto& entry : logRecords) {
        svDebitLogRecords.push_back(std::make_shared<SvDebitLogRecordAdapter>(entry.second, 0));
    }

    return svDebitLogRecords;
}

void CalypsoCardAdapter::setDfRatified(const bool dfRatified)
{
    mIsDfRatified = std::make_shared<bool>(dfRatified);
}

CalypsoCardClass CalypsoCardAdapter::getCardClass() const
{
    return mCalypsoCardClass;
}

const std::shared_ptr<DirectoryHeader> CalypsoCardAdapter::getDirectoryHeader() const
{
    return mDirectoryHeader;
}

CalypsoCard& CalypsoCardAdapter::setDirectoryHeader(
    const std::shared_ptr<DirectoryHeader> directoryHeader)
{
    mDirectoryHeader = directoryHeader;
    mIsDfInvalidated = (directoryHeader->getDfStatus() & 0x01) != 0;

    return *this;
}

const std::shared_ptr<ElementaryFile> CalypsoCardAdapter::getFileBySfi(const uint8_t sfi) const
{
    if (sfi == 0) {
        return nullptr;
    }

    for (const auto& ef : mFiles) {
        if (ef->getSfi() == sfi) {
            return ef;
        }
    }

    mLogger->warn("EF with SFI % is not found\n", sfi);

    return nullptr;
}

const std::shared_ptr<ElementaryFile> CalypsoCardAdapter::getFileByLid(const uint16_t lid) const
{
    for (const auto& ef : mFiles) {
        if (ef->getHeader() != nullptr && ef->getHeader()->getLid() == lid) {
            return ef;
        }
    }

    mLogger->warn("EF with LID % is not found\n", lid);

    return nullptr;
}

const std::map<const uint8_t, const std::shared_ptr<ElementaryFile>>
    CalypsoCardAdapter::getAllFiles() const
{
    std::map<const uint8_t, const std::shared_ptr<ElementaryFile>> res;
    for (const auto& ef : mFiles) {
        if (ef->getSfi() != 0) {
            res.insert({ef->getSfi(), ef});
        }
    }

    return res;
}

const std::vector<std::shared_ptr<ElementaryFile>>& CalypsoCardAdapter::getFiles() const
{
    return mFiles;
}

void CalypsoCardAdapter::updateCurrentSfi(const uint8_t sfi)
{
    if (sfi != 0) {
        mCurrentSfi = sfi;
    }
}

void CalypsoCardAdapter::updateCurrentLid(const uint16_t lid)
{
    if (lid != 0) {
        mCurrentLid = lid;
    }
}

const std::shared_ptr<ElementaryFileAdapter> CalypsoCardAdapter::getOrCreateFile()
{
    if (mCurrentSfi != 0) {
        /* Search by SFI */
        for (const auto& ef : mFiles) {
            if (ef->getSfi() == mCurrentSfi) {
                return std::dynamic_pointer_cast<ElementaryFileAdapter>(ef);
            }
        }
    } else if (mCurrentLid != 0) {
        /* Search by LID */
        for (const auto& ef : mFiles) {
            if (ef->getHeader() != nullptr && ef->getHeader()->getLid() == mCurrentLid) {
                return std::dynamic_pointer_cast<ElementaryFileAdapter>(ef);
            }
        }
    }

    /* Create a new EF with the provided SFI */
    const auto ef = std::make_shared<ElementaryFileAdapter>(mCurrentSfi);
    mFiles.push_back(ef);

    return ef;
}

bool CalypsoCardAdapter::isPinBlocked() const
{
    return getPinAttemptRemaining() == 0;
}

int CalypsoCardAdapter::getPinAttemptRemaining() const
{
    if (mPinAttemptCounter == nullptr) {
        throw IllegalStateException("PIN status has not been checked.");
    }

    return *mPinAttemptCounter.get();
}

void CalypsoCardAdapter::setPinAttemptRemaining(const int pinAttemptCounter)
{
    mPinAttemptCounter = std::make_shared<int>(pinAttemptCounter);
}

void CalypsoCardAdapter::setFileHeader(const uint8_t sfi,
                                       const std::shared_ptr<FileHeaderAdapter> header)
{
    updateCurrentSfi(sfi);
    updateCurrentLid(header->getLid());

    std::shared_ptr<ElementaryFileAdapter> ef = getOrCreateFile();
    if (ef->getHeader() == nullptr) {
        ef->setHeader(header);
    } else {
        std::dynamic_pointer_cast<FileHeaderAdapter>(ef->getHeader())
            ->updateMissingInfoFrom(header);
    }
}

void CalypsoCardAdapter::setContent(const uint8_t sfi,
                                    const int numRecord,
                                    const std::vector<uint8_t>& content)
{
    updateCurrentSfi(sfi);
    std::shared_ptr<ElementaryFileAdapter> ef = getOrCreateFile();
    std::dynamic_pointer_cast<FileDataAdapter>(ef->getData())->setContent(numRecord, content);
}

void CalypsoCardAdapter::setCounter(const uint8_t sfi,
                                    const int numCounter,
                                    const std::vector<uint8_t>& content)
{
    updateCurrentSfi(sfi);
    std::shared_ptr<ElementaryFileAdapter> ef = getOrCreateFile();
    std::dynamic_pointer_cast<FileDataAdapter>(ef->getData())->setCounter(numCounter, content);
}

void CalypsoCardAdapter::setContent(const uint8_t sfi,
                                    const int numRecord,
                                    const std::vector<uint8_t>& content,
                                    const int offset)
{
    updateCurrentSfi(sfi);
    std::shared_ptr<ElementaryFileAdapter> ef = getOrCreateFile();
    std::dynamic_pointer_cast<FileDataAdapter>(ef->getData())
        ->setContent(numRecord, content, offset);
}

void CalypsoCardAdapter::fillContent(const uint8_t sfi,
                                     const int numRecord,
                                     const std::vector<uint8_t>& content,
                                     const int offset)
{
    updateCurrentSfi(sfi);
    std::shared_ptr<ElementaryFileAdapter> ef = getOrCreateFile();
    std::dynamic_pointer_cast<FileDataAdapter>(ef->getData())
        ->fillContent(numRecord, content, offset);
}

void CalypsoCardAdapter::addCyclicContent(const uint8_t sfi, const std::vector<uint8_t> content)
{
    updateCurrentSfi(sfi);
    std::shared_ptr<ElementaryFileAdapter> ef = getOrCreateFile();
    std::dynamic_pointer_cast<FileDataAdapter>(ef->getData())->addCyclicContent(content);
}

void CalypsoCardAdapter::backupFiles()
{
    copyFiles(mFiles, mFilesBackup);
}

void CalypsoCardAdapter::restoreFiles()
{
    copyFiles(mFilesBackup, mFiles);
}

void CalypsoCardAdapter::copyFiles(const std::vector<std::shared_ptr<ElementaryFile>>& src,
                                   std::vector<std::shared_ptr<ElementaryFile>>& dest)
{
    dest.clear();
    for (const auto& file : src) {
        dest.push_back(std::make_shared<ElementaryFileAdapter>(file));
    }
}

const std::string& CalypsoCardAdapter::getPowerOnData() const
{
    return mPowerOnData;
}

const std::vector<uint8_t> CalypsoCardAdapter::getSelectApplicationResponse() const
{
    if (mSelectApplicationResponse == nullptr) {
        return std::vector<uint8_t>();
    }

    return mSelectApplicationResponse->getApdu();
}

void CalypsoCardAdapter::setCardChallenge(const std::vector<uint8_t>& cardChallenge)
{
    mCardChallenge = cardChallenge;
}

void CalypsoCardAdapter::setTraceabilityInformation(
    const std::vector<uint8_t>& traceabilityInformation)
{
    mTraceabilityInformation = traceabilityInformation;
}

void CalypsoCardAdapter::setSvOperationSignature(const std::vector<uint8_t>& svOperationSignature)
{
    mSvOperationSignature = svOperationSignature;
}

const std::vector<uint8_t>& CalypsoCardAdapter::getCardChallenge() const
{
    return mCardChallenge;
}

uint8_t CalypsoCardAdapter::getSvKvc() const
{
    return mSvKvc;
}

const std::vector<uint8_t>& CalypsoCardAdapter::getSvGetHeader() const
{
    if (mSvGetHeader.empty()) {
        throw IllegalStateException("SV Get Header not available.");
    }

    return mSvGetHeader;
}

const std::vector<uint8_t>& CalypsoCardAdapter::getSvGetData() const
{
    if (mSvGetData.empty()) {
        throw new IllegalStateException("SV Get Data not available.");
    }

    return mSvGetData;
}

const std::vector<uint8_t>& CalypsoCardAdapter::getSvOperationSignature() const
{
    return mSvOperationSignature;
}

std::ostream& operator<<(std::ostream& os, const CalypsoCardAdapter& cca)
{
    os << "CALYPSO_CARD_ADAPTER: {"
       << "SELECT_APPLICATION_RESPONSE: " << cca.mSelectApplicationResponse << ", "
       << "POWER_ON_DATA: " << cca.mPowerOnData << ", "
       << "IS_EXTENDED_MODE_SUPPORTED: " << cca.mIsExtendedModeSupported << ", "
       << "IS_RATIFICATION_ON_DESELECT_SUPPORTED: " << cca.mIsRatificationOnDeselectSupported <<", "
       << "IS_SV_FEATURE_AVAILABLE: " << cca.mIsSvFeatureAvailable << ", "
       << "IS_PIN_FEATURE_AVAILABLE: " << cca.mIsPinFeatureAvailable << ", "
       << "IS_PKI_MODE_SUPPORTED:" << cca.mIsPkiModeSupported << ", "
       << "IS_DF_INVALIDATED:" << cca.mIsDfInvalidated << ", "
       << "CALYPSO_CARD_CLASS: " << cca.mCalypsoCardClass << ", "
       << "CALYPSO_SERIAL_NUMBER: " << cca.mCalypsoSerialNumber << ", "
       << "STARTUP_INFO:" << cca.mStartupInfo << ", "
       << "PRODUCT_TYPE: " << cca.mProductType << ", "
       << "DF_NAME: " << cca.mDfName << ", "
       << "MODIFICATIONS_COUNTER_MAX: " << cca.mModificationsCounterMax << ", "
       << "IS_MODIFICATION_COUNTER_IN_BYTES: " << cca.mIsModificationCounterInBytes << ", "
       << "DIRECTORY_HEADER: " << cca.mDirectoryHeader << ", "
       << "FILES: " << cca.mFiles << ", "
       << "FILES_BACKUP: " << cca.mFilesBackup << ", "
       << "CURRENT_SFI: " << cca.mCurrentSfi << ", "
       << "CURRENT_LID: " << cca.mCurrentLid << ", "
       << "ID_DF_RATIFIED: " << cca.mIsDfRatified << ", "
       << "PIN_ATTEMPT_COUNTER: " << cca.mPinAttemptCounter << ", "
       << "SV_BALANCE: " << cca.mSvBalance << ", "
       << "SV_LAST_T_NUM: " << cca.mSvLastTNum << ", "
       << "SV_LOAD_LOG_RECORD: " << cca.mSvLoadLogRecord << ", "
       << "SV_DEBIT_LOG_RECORD: " << cca.mSvDebitLogRecord << ", "
       << "IS_HCE: " << cca.mIsHce << ", "
       << "CARD_CHALLENGE: " << cca.mCardChallenge << ", "
       << "TRACEABILITY_INFORMATION: " << cca.mTraceabilityInformation << ", "
       << "SV_KVC: " << cca.mSvKvc << ", "
       << "SV_GET_HEADER: " << cca.mSvGetHeader << ", "
       << "SV_GET_DATA: " << cca.mSvGetData << ", "
       << "SV_OPERATION_SIGNATURE: " << cca.mSvOperationSignature << ", "
       << "APPLICATION_SUB_TYPE: " << cca.mApplicationSubType << ", "
       << "APPLICATION_TYPE: " << cca.mApplicationType << ", "
       << "SESSION_MODIFICATION: " << cca.mSessionModification
       << "}";

       return os;
}

std::ostream& operator<<(std::ostream& os, const std::shared_ptr<CalypsoCardAdapter> cca)
{
    if (cca == nullptr) {
        os << "CALYPSO_CARD_ADAPTER: null";
    } else {
        os << *cca.get();
    }

    return os;
}

}
}
}
