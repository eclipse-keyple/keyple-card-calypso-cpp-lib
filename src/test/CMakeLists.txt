# *************************************************************************************************
# Copyright (c) 2021 Calypso Networks Association                                                 *
# https://www.calypsonet-asso.org/                                                                *
#                                                                                                 *
# See the NOTICE file(s) distributed with this work for additional information regarding          *
# copyright ownership.                                                                            *
#                                                                                                 *
# This program and the accompanying materials are made available under the terms of the Eclipse   *
# Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0                   *
#                                                                                                 *
# SPDX-License-Identifier: EPL-2.0                                                                *
# *************************************************************************************************/

SET(EXECTUABLE_NAME keyplecardcalypso_ut)

SET(CALYPSONET_CALYPSO_DIR  "../../../calypsonet-terminal-calypso-cpp-api")
SET(CALYPSONET_CARD_DIR     "../../../calypsonet-terminal-card-cpp-api")
SET(CALYPSONET_READER_DIR   "../../../calypsonet-terminal-reader-cpp-api")
SET(KEYPLE_COMMON_DIR       "../../../keyple-common-cpp-api")
SET(KEYPLE_SERVICE_DIR      "../../../keyple-service-cpp-lib")
SET(KEYPLE_RESOURCE_DIR     "../../../keyple-service-resource-cpp-lib")
SET(KEYPLE_UTIL_DIR         "../../../keyple-util-cpp-lib")

SET(KEYPLE_CALYPSO_LIB      "keyplecardcalypsocpplib")
SET(KEYPLE_SERVICE_LIB      "keypleservicecpplib")
SET(KEYPLE_UTIL_LIB         "keypleutilcpplib")

INCLUDE_DIRECTORIES(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../main
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/spi
    ${CMAKE_CURRENT_SOURCE_DIR}/../test/mock

    ${CALYPSONET_CALYPSO_DIR}/src/main
    ${CALYPSONET_CALYPSO_DIR}/src/main/card
    ${CALYPSONET_CALYPSO_DIR}/src/main/sam
    ${CALYPSONET_CALYPSO_DIR}/src/main/transaction

    ${CALYPSONET_CARD_DIR}/src/main
    ${CALYPSONET_CARD_DIR}/src/main/spi

    ${CALYPSONET_READER_DIR}/src/main
    ${CALYPSONET_READER_DIR}/src/main/selection
    ${CALYPSONET_READER_DIR}/src/main/selection/spi
    ${CALYPSONET_READER_DIR}/src/main/spi

    ${KEYPLE_COMMON_DIR}/src/main

    ${KEYPLE_RESOURCE_DIR}/src/main/spi

    ${KEYPLE_SERVICE_DIR}/src/main

    ${KEYPLE_UTIL_DIR}/src/main
    ${KEYPLE_UTIL_DIR}/src/main/cpp
    ${KEYPLE_UTIL_DIR}/src/main/cpp/exception
)

ADD_EXECUTABLE(
    ${EXECTUABLE_NAME}

    ${CMAKE_CURRENT_SOURCE_DIR}/MainTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoCardAdapterTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoCardSelectionAdapterTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoExtensionServiceTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoSamSelectionAdapterTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CardTransactionManagerAdapterTest.cpp
)

# Add Google Test
SET(GOOGLETEST_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
INCLUDE(CMakeLists.txt.googletest)

TARGET_LINK_LIBRARIES(
    ${EXECTUABLE_NAME}

    gtest
    gmock

    ${KEYPLE_CALYPSO_LIB}
    ${KEYPLE_SERVICE_LIB}
    ${KEYPLE_UTIL_LIB}
)
