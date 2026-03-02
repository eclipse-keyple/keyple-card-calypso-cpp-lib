#******************************************************************************
#* Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
#*                                                                            *
#* See the NOTICE file(s) distributed with this work for additional           *
#* information regarding copyright ownership.                                 *
#*                                                                            *
#* This program and the accompanying materials are made available under the   *
#* terms of the Eclipse Public License 2.0 which is available at              *
#* http://www.eclipse.org/legal/epl-2.0                                       *
#*                                                                            *
#* SPDX-License-Identifier: EPL-2.0                                           *
#******************************************************************************/

SET(LIBRARY_NAME keyplecardcalypsocpplib)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DKEYPLECARDCALYPSO_EXPORT")

# Include deps
INCLUDE("CMakeLists.txt.keyple-card-calypso-crypto-legacysam")
INCLUDE("CMakeLists.txt.keyple-common")
INCLUDE("CMakeLists.txt.keyple-util")
INCLUDE("CMakeLists.txt.keypop-card")
INCLUDE("CMakeLists.txt.keypop-reader")
INCLUDE("CMakeLists.txt.keypop-calypso-card")
INCLUDE("CMakeLists.txt.keypop-calypso-crypto-asymmetric")
INCLUDE("CMakeLists.txt.keypop-calypso-crypto-legacysam")
INCLUDE("CMakeLists.txt.keypop-calypso-crypto-symmetric")

ADD_LIBRARY(

    ${LIBRARY_NAME}

    ${LIBRARY_TYPE}

    ${CMAKE_CURRENT_SOURCE_DIR}/AsymmetricCryptoSecuritySettingAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoCardAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoCardApiFactoryAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoCardClass.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoCardConstant.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoCardSelectionExtensionAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoExtensionService.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CardCommandRef.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Command.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandAppendRecord.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandChangeKey.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandChangePin.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandCloseSecureSession.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandGenerateAsymmetricKeyPair.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandGetChallenge.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandGetDataCardPublicKey.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandGetDataCertificate.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandGetDataEfList.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandGetDataFci.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandGetDataFcp.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandGetDataTraceabilityInformation.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandIncreaseOrDecrease.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandIncreaseOrDecreaseMultiple.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandInvalidate.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandManageSession.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandOpenSecureSession.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandPutData.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandRatification.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandReadBinary.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandReadRecordMultiple.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandReadRecords.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandRehabilitate.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandSearchRecordMultiple.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandSelectFile.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandSvGet.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandSvDebitOrUndebit.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandSvReload.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandUpdateRecord.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandUpdateOrWriteBinary.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandVerifyPin.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandWriteRecord.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/DirectoryHeaderAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/DtoAdapters.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ElementaryFileAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/DtoAdapters.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/FileDataAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/FileHeaderAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/FreeTransactionManagerAdapter.cpp
    # ${CMAKE_CURRENT_SOURCE_DIR}/SamControlSamTransactionManagerAdapter.cpp
    # ${CMAKE_CURRENT_SOURCE_DIR}/SamTransactionManagerAdapter.cpp
    # ${CMAKE_CURRENT_SOURCE_DIR}/SamUtilAdapter.cpp
    # ${CMAKE_CURRENT_SOURCE_DIR}/SearchCommandDataAdapter.cpp
    # ${CMAKE_CURRENT_SOURCE_DIR}/SvDebitLogRecordJsonDeserializerAdapter.cpp
    # ${CMAKE_CURRENT_SOURCE_DIR}/SvLoadLogRecordJsonDeserializerAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SecureExtendedModeTransactionManagerAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SecurePkiModeTransactionManagerAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SecureRegularModeTransactionManagerAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SecureSymmetricCryptoTransactionManagerAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SecureTransactionManagerAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SymmetricCryptoSecuritySettingAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/TransactionManagerAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/cpp/SecureRandom.cpp
)

TARGET_INCLUDE_DIRECTORIES(

    ${LIBRARY_NAME}

    PUBLIC

    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
)

TARGET_LINK_LIBRARIES(

    ${LIBRARY_NAME}

    PUBLIC

    Keyple::Card::Calypso::Crypto::LegacySam
    Keyple::Common
    Keyple::Util
    Keypop::Calypso::Card
    Keypop::Calypso::Crypto::Asymmetric
    Keypop::Calypso::Crypto::LegacySam
    Keypop::Calypso::Crypto::Symmetric
    Keypop::Card
    Keypop::Reader
)

ADD_LIBRARY(

    Keyple::Card::Calypso

    ALIAS

    ${LIBRARY_NAME}
)
