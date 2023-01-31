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
 **************************************************************************************************/

#include "CmdSamReadKeyParameters.h"

#include <sstream>

/* Keyple Card Calypso */
#include "CalypsoSamCounterOverflowException.h"
#include "CalypsoSamDataAccessException.h"
#include "CalypsoSamIllegalParameterException.h"
#include "SamUtilAdapter.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "IllegalArgumentException.h"
#include "IllegalStateException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp::exception;

const CalypsoSamCommand CmdSamReadKeyParameters::mCommand = CalypsoSamCommand::READ_KEY_PARAMETERS;
const int CmdSamReadKeyParameters::MAX_WORK_KEY_REC_NUMB = 126;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamReadKeyParameters::STATUS_TABLE = initStatusTable();

CmdSamReadKeyParameters::CmdSamReadKeyParameters(const CalypsoSam::ProductType productType)
: AbstractSamCommand(mCommand, 0)
{
    const uint8_t cla = SamUtilAdapter::getClassByte(productType);
    
    const uint8_t p2 = 0xE0;
    const std::vector<uint8_t> sourceKeyId = {0x00, 0x00};

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, mCommand.getInstructionByte(), 0x00, p2, sourceKeyId, 0x00)));
}

CmdSamReadKeyParameters::CmdSamReadKeyParameters(const CalypsoSam::ProductType productType,
                                                 const uint8_t kif)
: AbstractSamCommand(mCommand, 0)
{
    const uint8_t cla = SamUtilAdapter::getClassByte(productType);
    
    const uint8_t p2 = 0xC0;
    std::vector<uint8_t> sourceKeyId = {0x00, 0x00};

    sourceKeyId[0] = kif;

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, mCommand.getInstructionByte(), 0x00, p2, sourceKeyId, 0x00)));
}

CmdSamReadKeyParameters::CmdSamReadKeyParameters(const CalypsoSam::ProductType productType,
                                                 const uint8_t kif,
                                                 const uint8_t kvc)
: AbstractSamCommand(mCommand, 0)
{
    const uint8_t cla = SamUtilAdapter::getClassByte(productType);
    
    const uint8_t p2 = 0xF0;
    std::vector<uint8_t> sourceKeyId = {0x00, 0x00};

    sourceKeyId[0] = kif;
    sourceKeyId[1] = kvc;

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, mCommand.getInstructionByte(), 0x00, p2, sourceKeyId, 0x00)));
}

CmdSamReadKeyParameters::CmdSamReadKeyParameters(const CalypsoSam::ProductType productType,
                                                 const SourceRef sourceKeyRef, 
                                                 const int recordNumber)
: AbstractSamCommand(mCommand, 0)
{
    if (recordNumber < 1 || recordNumber > MAX_WORK_KEY_REC_NUMB) {
        throw IllegalArgumentException("Record Number must be between 1 and " + 
                                       std::to_string(MAX_WORK_KEY_REC_NUMB) + 
                                       ".");
    }

    const uint8_t cla = SamUtilAdapter::getClassByte(productType);
    
    uint8_t p2;
    std::vector<uint8_t> sourceKeyId = {0x00, 0x00};

    switch (sourceKeyRef) {
    case SourceRef::WORK_KEY:
        p2 = static_cast<uint8_t>(recordNumber);
        break;
    case SourceRef::SYSTEM_KEY:
        p2 = static_cast<uint8_t>(0xC0 + recordNumber);
        break;
    default:
        std::stringstream ss;
        ss << sourceKeyRef;
        throw IllegalStateException("Unsupported SourceRef parameter " + 
                                    ss.str());
    }

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, mCommand.getInstructionByte(), 0x00, p2, sourceKeyId, 0x00)));
}

CmdSamReadKeyParameters::CmdSamReadKeyParameters(const CalypsoSam::ProductType productType,
                                                 const uint8_t kif, 
                                                 const NavControl navControl)
: AbstractSamCommand(mCommand, 0)
{
    const uint8_t cla = SamUtilAdapter::getClassByte(productType);
    
    uint8_t p2;
    std::vector<uint8_t> sourceKeyId = {0x00, 0x00};

    switch (navControl) {
    case NavControl::FIRST:
        p2 = 0xF8;
        break;
    case NavControl::NEXT:
        p2 = 0xFA;
        break;
    default:
        std::stringstream ss;
        ss << navControl;
        throw IllegalStateException("Unsupported NavControl parameter " + 
                                    ss.str());
    }

    sourceKeyId[0] = kif;
    
    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, mCommand.getInstructionByte(), 0x00, p2, sourceKeyId, 0x00)));
}

const std::vector<uint8_t> CmdSamReadKeyParameters::getKeyParameters() const
{
    return isSuccessful() ? getApduResponse()->getDataOut() : std::vector<uint8_t>();
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamReadKeyParameters::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractSamCommand::STATUS_TABLE;

    m.insert({0x6700,
              std::make_shared<StatusProperties>("Incorrect Lc.",
                                                 typeid(CalypsoSamIllegalParameterException))});
    m.insert({0x6900,
              std::make_shared<StatusProperties>("An event counter cannot be incremented.",
                                                 typeid(CalypsoSamCounterOverflowException))});
    m.insert({0x6A00,
              std::make_shared<StatusProperties>("Incorrect P2.",
                                                 typeid(CalypsoSamIllegalParameterException))});
    m.insert({0x6A83,
              std::make_shared<StatusProperties>("Record not found: key to read not found.",
                                                 typeid(CalypsoSamDataAccessException))});
    m.insert({0x6200,
              std::make_shared<StatusProperties>("Correct execution with warning: data not signed.",
                                                 typeid(nullptr))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdSamReadKeyParameters::getStatusTable() const
{
    return STATUS_TABLE;
}

/* SOURCE REF ------------------------------------------------------------------------------------*/

std::ostream& operator<<(std::ostream& os, const CmdSamReadKeyParameters::SourceRef& sr)
{
    os << "SOURCE_REF = ";

    switch (sr) {
    case CmdSamReadKeyParameters::SourceRef::WORK_KEY:
        os << "WORK_KEY";
        break;
    case CmdSamReadKeyParameters::SourceRef::SYSTEM_KEY:
        os << "SYSTEM_KEY";
        break;
    default:
        os << "UNKONWN";
        break;
    }

    return os;
}

/* NAV CONTROL ---------------------------------------------------------------------------------- */

std::ostream& operator<<(std::ostream& os, const CmdSamReadKeyParameters::NavControl& nc)
{
    os << "NAV_CONTROL = ";

    switch (nc) {
    case CmdSamReadKeyParameters::NavControl::FIRST:
        os << "FIRST";
        break;
    case CmdSamReadKeyParameters::NavControl::NEXT:
        os << "NEXT";
        break;
    default:
        os << "UNKONWN";
        break;
    }

    return os;
}

}
}
}
