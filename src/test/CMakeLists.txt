# *****************************************************************************
# Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/     *
#                                                                             *
# This program and the accompanying materials are made available under the    *
# terms of the MIT License which is available at                              *
# https://opensource.org/licenses/MIT.                                        *
#                                                                             *
# SPDX-License-Identifier: MIT                                                *
# *****************************************************************************/

SET(EXECTUABLE_NAME keyplecardcalypso_ut)

INCLUDE_DIRECTORIES(

    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/mock
)

ADD_EXECUTABLE(

    ${EXECTUABLE_NAME}

    ${CMAKE_CURRENT_SOURCE_DIR}/AbstractTransactionManagerTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/AsymmetricCryptoSecuritySettingAdapterTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoCardAdapterTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoCardSelectionExtensionAdapterTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CalypsoExtensionServiceTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/FileDataAdapterTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/FreeTransactionManagerAdapterTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/MainTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SecureExtendedModeTransactionManagerAdapterTest.cpp
    # ${CMAKE_CURRENT_SOURCE_DIR}/SecureRegularModeTransactionManagerAdapterTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SvDebitLogRecordTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SvLoadLogRecordTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SymmetricCryptoSecuritySettingAdapterTest.cpp
)

TARGET_INCLUDE_DIRECTORIES(

    ${EXECTUABLE_NAME}

    PUBLIC

    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Add Google Test
SET(GOOGLETEST_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
INCLUDE("CMakeLists.txt.googletest")

TARGET_LINK_LIBRARIES(

    ${EXECTUABLE_NAME}

    PRIVATE

    gtest
    gmock

    Keyple::Card::Calypso
)
