/**************************************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/                        *
 *                                                                                                *
 * See the NOTICE file(s) distributed with this work for additional information regarding         *
 * copyright ownership.                                                                           *
 *                                                                                                *
 * This program and the accompanying materials are made available under the terms of the Eclipse  *
 * Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0                  *
 *                                                                                                *
 * SPDX-License-Identifier: EPL-2.0                                                               *
 ***********************************"***************************************************************/

#include "CalypsoSamAdapter.h"

#include <sstream>

/* Keyple Core Util */
#include "HexUtil.h"
#include "IllegalStateException.h"
#include "Pattern.h"
#include "System.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;
using namespace keyple::core::util::cpp::exception;

CalypsoSamAdapter::CalypsoSamAdapter(
    const std::shared_ptr<CardSelectionResponseApi> cardSelectionResponse)
{
    /* In the case of a SAM, the power-on data corresponds to the ATR of the card */
    mPowerOnData = cardSelectionResponse->getPowerOnData();
    if (mPowerOnData.empty()) {
        throw IllegalStateException("ATR should not be empty.");
    }

    mSerialNumber = std::vector<uint8_t>(4);

    /*
     * Extract the historical bytes from T3 to T12
     * CL-SAM-ATR.1
     */
    const std::string extractRegex = "3B(.{6}|.{10})805A(.{20})829000";
    std::unique_ptr<Pattern> pattern = Pattern::compile(extractRegex);

    /* To use */
    std::unique_ptr<Matcher> matcher = pattern->matcher(mPowerOnData);
    if (matcher->find(0)) {
        const std::vector<uint8_t> atrSubElements = HexUtil::toByteArray(matcher->group(2));
        mPlatform = atrSubElements[0];
        mApplicationType = atrSubElements[1];
        mApplicationSubType = atrSubElements[2];
        mSoftwareIssuer = atrSubElements[3];
        mSoftwareVersion = atrSubElements[4];
        mSoftwareRevision = atrSubElements[5];

        /* Determine SAM product type from Application Subtype */
        switch (mApplicationSubType) {
        case 0xC1:
            mSamProductType = mSoftwareIssuer == 0x08 ? ProductType::HSM_C1 : ProductType::SAM_C1;
            break;
        case 0xD0:
        case 0xD1:
        case 0xD2:
            mSamProductType = ProductType::SAM_S1DX;
            break;
        case 0xE1:
            mSamProductType = ProductType::SAM_S1E1;
            break;
        default:
            mSamProductType = ProductType::UNKNOWN;
            break;
        }


        System::arraycopy(atrSubElements, 6, mSerialNumber, 0, 4);

        std::stringstream ss;
        ss << "SAM " << mSamProductType
           << "PLATFORM = " << mPlatform << ", "
           << "APPTYPE = " << mApplicationType << "h, "
           << "APPSUBTYPE = " << mApplicationSubType << "h, "
           << "SWISSUER = " << mSoftwareIssuer << "h, "
           << "SWVERSION = " << mSoftwareVersion << "h, "
           << "SWREVISION = " << mSoftwareRevision;
        mLogger->trace("%\n", ss.str());
        mLogger->trace("SAM SERIALNUMBER = %\n", HexUtil::toHex(mSerialNumber));

    } else {
        mSamProductType = ProductType::UNKNOWN;
        mPlatform = 0;
        mApplicationType = 0;
        mApplicationSubType = 0;
        mSoftwareIssuer = 0;
        mSoftwareVersion = 0;
        mSoftwareRevision = 0;
    }
}

uint8_t CalypsoSamAdapter::getClassByte(const CalypsoSam::ProductType type)
{
    /* CL-CLA-SAM.1 */
    if (type == CalypsoSam::ProductType::SAM_S1DX ||
        type == CalypsoSam::ProductType::CSAM_F) {
        return 0x94;
    }

    return 0x80;
}

uint8_t CalypsoSamAdapter::getClassByte() const
{
    return getClassByte(mSamProductType);
}

int CalypsoSamAdapter::getMaxDigestDataLength() const
{
    switch (mSamProductType) {
    case CalypsoSam::ProductType::SAM_C1:
    case CalypsoSam::ProductType::HSM_C1:
        return 255;
    case CalypsoSam::ProductType::SAM_S1DX:
        return 70;
    case CalypsoSam::ProductType::SAM_S1E1:
        return 240;
    case CalypsoSam::ProductType::CSAM_F:
        return 247;
    default:
        return 0;
    }
}

const std::vector<uint8_t> CalypsoSamAdapter::getSelectApplicationResponse() const
{
    return std::vector<uint8_t>(0);
}

const std::string& CalypsoSamAdapter::getPowerOnData() const
{
    return mPowerOnData;
}

CalypsoSam::ProductType CalypsoSamAdapter::getProductType() const
{
    return mSamProductType;
}

const std::string CalypsoSamAdapter::getProductInfo() const
{
    std::stringstream ss;
    ss << "Type: " << getProductType() << ", S/N: " << HexUtil::toHex(getSerialNumber());

    return ss.str();
}

const std::vector<uint8_t>& CalypsoSamAdapter::getSerialNumber() const
{
    return mSerialNumber;
}

uint8_t CalypsoSamAdapter::getPlatform() const
{
    return mPlatform;
}

uint8_t CalypsoSamAdapter::getApplicationType() const
{
    return mApplicationType;
}

uint8_t CalypsoSamAdapter::getApplicationSubType() const
{
    return mApplicationSubType;
}

uint8_t CalypsoSamAdapter::getSoftwareIssuer() const
{
    return mSoftwareIssuer;
}

uint8_t CalypsoSamAdapter::getSoftwareVersion() const
{
    return mSoftwareVersion;
}

uint8_t CalypsoSamAdapter::getSoftwareRevision() const
{
    return mSoftwareRevision;
}

void CalypsoSamAdapter::putEventCounter(const int eventCounterNumber, const int eventCounterValue)
{
    mEventCounters.insert({eventCounterNumber, eventCounterValue});
}

void CalypsoSamAdapter::putEventCeiling(const int eventCeilingNumber, const int eventCeilingValue)
{
    mEventCeilings.insert({eventCeilingNumber, eventCeilingValue});
}

// std::shared_ptr<int> CalypsoSamAdapter::getEventCounter(const int eventCounterNumber) const
// {
//     const auto it = mEventCounters.find(eventCounterNumber);
//     if (it != mEventCounters.end()) {
//         return std::make_shared<int>(it->second);
//     } else {
//         return nullptr;
//     }
// }

// const std::map<int, int>& CalypsoSamAdapter::getEventCounters() const
// {
//     return mEventCounters;
// }

// std::shared_ptr<int> CalypsoSamAdapter::getEventCeiling(const int eventCeilingNumber) const
// {
//     const auto it = mEventCeilings.find(eventCeilingNumber);
//     if (it != mEventCeilings.end()) {
//         return std::make_shared<int>(it->second);
//     } else {
//         return nullptr;
//     }
// }

// const std::map<int, int>& CalypsoSamAdapter::getEventCeilings() const
// {
//     return mEventCeilings;
// }

}
}
}
