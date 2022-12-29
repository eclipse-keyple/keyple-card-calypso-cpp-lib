# *************************************************************************************************
# Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/                         *
#                                                                                                 *
# See the NOTICE file(s) distributed with this work for additional information regarding          *
# copyright ownership.                                                                            *
#                                                                                                 *
# This program and the accompanying materials are made available under the terms of the Eclipse   *
# Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0                   *
#                                                                                                 *
# SPDX-License-Identifier: EPL-2.0                                                                *
# *************************************************************************************************/

SET(LIBRARY_NAME keyplecardcalypsocpplib)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DKEYPLECARDCALYPSO_EXPORT")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-undefined-var-template")

ADD_LIBRARY(
    ${LIBRARY_NAME}

    ${LIBRARY_TYPE}

    ${CMAKE_CURRENT_SOURCE_DIR}/AbstractApduCommand.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/AbstractCardCommand.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/AbstractSamCommand.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ApduRequestAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoCardAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoCardClass.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoCardCommand.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoCardConstant.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoCardSelectionAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoCardUtilAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoExtensionService.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoSamAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoSamCommand.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoSamResourceProfileExtensionAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoSamSecurityContextException.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoSamSelectionAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CardControlSamTransactionManagerAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CardRequestAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CardSecuritySettingAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CardSelectionRequestAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CardSelectorAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CardTransactionManagerAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardAppendRecord.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardChangeKey.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardChangePin.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardCloseSession.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardGetChallenge.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardGetDataFci.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardGetDataEfList.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardGetDataFcp.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardGetDataTraceabilityInformation.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardIncreaseOrDecrease.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardIncreaseOrDecreaseMultiple.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardInvalidate.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardOpenSession.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardRatificationBuilder.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardReadBinary.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardReadRecordMultiple.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardReadRecords.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardRehabilitate.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardSearchRecordMultiple.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardSelectFile.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardSvDebitOrUndebit.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardSvGet.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardSvReload.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardUpdateOrWriteBinary.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardUpdateRecord.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardVerifyPin.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdCardWriteRecord.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdSamCardCipherPin.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdSamCardGenerateKey.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdSamDataCipher.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdSamDigestAuthenticate.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdSamDigestClose.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdSamDigestInit.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdSamDigestUpdate.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdSamGetChallenge.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdSamGiveRandom.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdSamPsoComputeSignature.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdSamPsoVerifySignature.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdSamReadCeilings.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdSamReadEventCounter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdSamReadKeyParameters.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdSamSelectDiversifier.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdSamSvCheck.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdSamSvPrepareDebitOrUndebit.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdSamSvPrepareLoad.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdSamUnlock.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdSamWriteKey.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/DirectoryHeaderAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ElementaryFileAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/FileDataAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/FileHeaderAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SamControlSamTransactionManagerAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SamTransactionManagerAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SamUtilAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SearchCommandDataAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SvDebitLogRecordAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SvLoadLogRecordAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SvDebitLogRecordJsonDeserializerAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SvLoadLogRecordJsonDeserializerAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/TraceableSignatureComputationDataAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/TraceableSignatureVerificationDataAdapter.cpp
)

TARGET_INCLUDE_DIRECTORIES(
    ${LIBRARY_NAME}

    PUBLIC

    ${CMAKE_CURRENT_SOURCE_DIR}
    cpp
    cpp/exception
)

# Careful, link order matters here as there are includes with the same name, and we cannot
# discriminate based on path
TARGET_LINK_LIBRARIES(

    ${LIBRARY_NAME}

    PUBLIC

    CalypsoNet::TerminalCalypso
    Keyple::ServiceResource
)

ADD_LIBRARY(Keyple::CardCalypso ALIAS ${LIBRARY_NAME})
