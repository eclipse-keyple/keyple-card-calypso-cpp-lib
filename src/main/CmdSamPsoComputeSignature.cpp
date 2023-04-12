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

#include "CmdSamPsoComputeSignature.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "Arrays.h"
#include "ByteArrayUtil.h"
#include "System.h"

/* Keyple Card Calypso */
#include "CalypsoSamAccessForbiddenException.h"
#include "CalypsoSamCounterOverflowException.h"
#include "CalypsoSamDataAccessException.h"
#include "CalypsoSamIllegalParameterException.h"
#include "CalypsoSamIncorrectInputDataException.h"
#include "SamUtilAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamPsoComputeSignature::STATUS_TABLE = initStatusTable();

CmdSamPsoComputeSignature::CmdSamPsoComputeSignature(
  const std::shared_ptr<CalypsoSamAdapter> calypsoSam,
  const std::shared_ptr<TraceableSignatureComputationDataAdapter> data)
: AbstractSamCommand(CalypsoSamCommand::PSO_COMPUTE_SIGNATURE, 0, calypsoSam),
  mData(data)
{
    const uint8_t cla = SamUtilAdapter::getClassByte(calypsoSam->getProductType());
    const uint8_t ins = getCommandRef().getInstructionByte();
    const uint8_t p1 = 0x9E;
    const uint8_t p2 = 0x9A;

    /* DataIn */
    const int messageOffset = data->isSamTraceabilityMode() ? 6 : 4;
    const int messageSize = static_cast<int>(data->getData().size());
    std::vector<uint8_t> dataIn(static_cast<uint64_t>(messageOffset) +
                                static_cast<uint64_t>(messageSize));

    /* SignKeyNum: Selection of the key by KIF and KVC given in the incoming data */
    dataIn[0] = 0xFF;

    /* SignKeyRef: KIF and KVC of the signing key */
    dataIn[1] = data->getKif();
    dataIn[2] = data->getKvc();

    /**
     * OpMode: Operating mode, equal to XYh, with:
     * X: Mode
     */
    uint8_t opMode = 0; /* %0000 Normal mode */
    if (data->isSamTraceabilityMode()) {
        if (data->isPartialSamSerialNumber()) {
            opMode |= 4; /* %x100 */
        } else {
            opMode |= 6; /* %x110 */
        }
    }
    if (data->isBusyMode()) {
        opMode |= 8; /* %1xx0 */
    }
    opMode <<= 4;

    /* Y: Signature size (in bytes) */
    opMode |= data->getSignatureSize();
    dataIn[3] = opMode;

    /* TraceOffset (optional): Bit offset in MessageIn of the SAM traceability data */
    if (data->isSamTraceabilityMode()) {

        ByteArrayUtil::copyBytes(data->getTraceabilityOffset(), dataIn, 4, 2);
    }

    /* MessageIn: Message to sign */
    System::arraycopy(data->getData(), 0, dataIn, messageOffset, messageSize);

    setApduRequest(std::make_shared<ApduRequestAdapter>(ApduUtil::build(cla, ins, p1, p2, dataIn)));
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdSamPsoComputeSignature::getStatusTable() const
{
    return STATUS_TABLE;
}

void CmdSamPsoComputeSignature::parseApduResponse(
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    AbstractSamCommand::parseApduResponse(apduResponse);

    if (static_cast<int>(apduResponse->getDataOut().size()) > 0) {
        if (mData->isSamTraceabilityMode()) {
            mData->setSignedData(Arrays::copyOf(apduResponse->getDataOut(),
                                                mData->getData().size()));
        } else {
            mData->setSignedData(mData->getData());
        }

        mData->setSignature(
            Arrays::copyOfRange(
                apduResponse->getDataOut(),
                apduResponse->getDataOut().size() - mData->getSignatureSize(),
                apduResponse->getDataOut().size()));
    }
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamPsoComputeSignature::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractSamCommand::STATUS_TABLE;

    m.insert({0x6700,
              std::make_shared<StatusProperties>("Incorrect Lc.",
                                                 typeid(CalypsoSamIllegalParameterException))});
    m.insert({0x6900,
              std::make_shared<StatusProperties>("An event counter cannot be incremented.",
                                                 typeid(CalypsoSamCounterOverflowException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Preconditions not satisfied.",
                                                 typeid(CalypsoSamAccessForbiddenException))});
    m.insert({0x6A80,
              std::make_shared<StatusProperties>("Incorrect value in the incoming data.",
                                                 typeid(CalypsoSamIncorrectInputDataException))});
    m.insert({0x6A83,
              std::make_shared<StatusProperties>("Record not found: signing key not found.",
                                                 typeid(CalypsoSamDataAccessException))});
    m.insert({0x6B00,
              std::make_shared<StatusProperties>("Incorrect P1 or P2.",
                                                 typeid(CalypsoSamIllegalParameterException))});

    return m;
}

}
}
}
