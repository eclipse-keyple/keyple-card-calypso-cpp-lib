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

#include "CmdSamDataCipher.h"

/* Keyple Card Calypso */
#include "CalypsoCardAdapter.h"
#include "CalypsoSamAccessForbiddenException.h"
#include "CalypsoSamCounterOverflowException.h"
#include "CalypsoSamDataAccessException.h"
#include "CalypsoSamDataAccessException.h"
#include "CalypsoSamIllegalParameterException.h"
#include "CalypsoSamSecurityDataException.h"
#include "SamUtilAdapter.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "Arrays.h"
#include "System.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamDataCipher::STATUS_TABLE = initStatusTable();

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamDataCipher::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        CmdSamDataCipher::STATUS_TABLE;

    m.insert({0x6700,
              std::make_shared<StatusProperties>("Incorrect Lc.",
                                                 typeid(CalypsoSamIllegalParameterException))});
    m.insert({0x6900,
              std::make_shared<StatusProperties>("An event counter cannot be incremented.",
                                                 typeid(CalypsoSamCounterOverflowException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>(
                  "Preconditions not satisfied:\n" \
                  "- The SAM is locked.\n" \
                  "- Cipher or sign forbidden (DataCipherEnableBit of PAR5 is 0).\n" \
                  "- Ciphering or signing mode, and ciphering forbidden (CipherEnableBit of PAR1 " \
                  "is 0).\n" \
                  "- Decipher mode, and deciphering forbidden (DecipherDataEnableBit of PAR1 is " \
                  "0).\n" \
                  "- AES key.",
                                                 typeid(CalypsoSamAccessForbiddenException))});
    m.insert({0x6A83,
              std::make_shared<StatusProperties>("Record not found: ciphering key not found.",
                                                 typeid(CalypsoSamDataAccessException))});
    m.insert({0x6B00,
              std::make_shared<StatusProperties>("Incorrect P1.",
                                                 typeid(CalypsoSamIllegalParameterException))});

    return m;
}

CmdSamDataCipher::CmdSamDataCipher(
  const CalypsoSam::ProductType productType,
  const std::shared_ptr<BasicSignatureComputationDataAdapter> signatureComputationData,
  const std::shared_ptr<BasicSignatureVerificationDataAdapter> signatureVerificationData)
: AbstractSamCommand(CalypsoSamCommand::DATA_CIPHER, 0),
  mSignatureComputationData(signatureComputationData),
  mSignatureVerificationData(signatureVerificationData)
{
    const uint8_t cla = SamUtilAdapter::getClassByte(productType);
    const uint8_t ins = getCommandRef().getInstructionByte();
    const uint8_t p1 = 0x40; /* TODO implement the other modes (cipher, decipher) */
    const uint8_t p2 = 0x00;

    std::vector<uint8_t> dataIn;

    if (signatureComputationData != nullptr) {
        dataIn = std::vector<uint8_t>(2 + signatureComputationData->getData().size());
        dataIn[0] = signatureComputationData->getKif();
        dataIn[1] = signatureComputationData->getKvc();
        System::arraycopy(signatureComputationData->getData(),
                          0,
                          dataIn,
                          2,
                          signatureComputationData->getData().size());
    } else if (signatureVerificationData != nullptr) {
        dataIn = std::vector<uint8_t>(2 + signatureVerificationData->getData().size());
        dataIn[0] = signatureVerificationData->getKif();
        dataIn[1] = signatureVerificationData->getKvc();
        System::arraycopy(signatureVerificationData->getData(),
                          0,
                          dataIn,
                          2,
                          signatureVerificationData->getData().size());
    } else {
        dataIn = std::vector<uint8_t>(0);
    }

    setApduRequest(std::make_shared<ApduRequestAdapter>(ApduUtil::build(cla, ins, p1, p2, dataIn)));
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdSamDataCipher::getStatusTable() const
{
    return STATUS_TABLE;
}

AbstractSamCommand& CmdSamDataCipher::setApduResponse(
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    AbstractSamCommand::setApduResponse(apduResponse);

    if (apduResponse->getDataOut().size() > 0) {
        if (mSignatureComputationData != nullptr) {
            mSignatureComputationData->setSignature(
                Arrays::copyOfRange(apduResponse->getDataOut(),
                                    0,
                                    mSignatureComputationData->getSignatureSize()));

        } else if (mSignatureVerificationData != nullptr) {
            const std::vector<uint8_t> computedSignature =
                Arrays::copyOfRange(apduResponse->getDataOut(),
                                    0,
                                    mSignatureVerificationData->getSignature().size());
            mSignatureVerificationData->setSignatureValid(
                Arrays::equals(computedSignature, mSignatureVerificationData->getSignature()));
        }
    }

    return *this;
}

void CmdSamDataCipher::checkStatus()
{
    AbstractSamCommand::checkStatus();

    if (mSignatureVerificationData != nullptr && !mSignatureVerificationData->isSignatureValid()) {
        throw CalypsoSamSecurityDataException("Incorrect signature.", getCommandRef(), 0);
    }
}

}
}
}
