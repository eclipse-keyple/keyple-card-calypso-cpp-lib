/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the MIT License which is available at                             *
 * https://opensource.org/licenses/MIT.                                       *
 *                                                                            *
 * SPDX-License-Identifier: MIT                                               *
 ******************************************************************************/

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "keypop/calypso/card/transaction/spi/CardTransactionCryptoExtension.hpp"
#include "keypop/calypso/crypto/symmetric/SvCommandSecurityDataApi.hpp"
#include "keypop/calypso/crypto/symmetric/spi/SymmetricCryptoCardTransactionManagerSpi.hpp"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using keypop::calypso::card::transaction::spi::CardTransactionCryptoExtension;
using keypop::calypso::crypto::symmetric::SvCommandSecurityDataApi;
using keypop::calypso::crypto::symmetric::spi::
    SymmetricCryptoCardTransactionManagerSpi;

class SymmetricCryptoCardTransactionManagerMock final
: public SymmetricCryptoCardTransactionManagerSpi,
  public CardTransactionCryptoExtension {
public:
    SymmetricCryptoCardTransactionManagerMock() = default;

    ~SymmetricCryptoCardTransactionManagerMock() = default;

    MOCK_METHOD(
        (std::vector<std::uint8_t>),
        initTerminalSecureSessionContext,
        (),
        (override));

    MOCK_METHOD(
        (void),
        initTerminalSessionMac,
        (const std::vector<std::uint8_t>&,
         const std::uint8_t,
         const std::uint8_t),
        (override));

    MOCK_METHOD(
        (std::vector<std::uint8_t>),
        updateTerminalSessionMac,
        (const std::vector<std::uint8_t>&),
        (override));

    MOCK_METHOD(
        (std::vector<std::uint8_t>),
        finalizeTerminalSessionMac,
        (),
        (override));

    MOCK_METHOD(
        (std::vector<std::uint8_t>),
        generateTerminalSessionMac,
        (),
        (override));

    MOCK_METHOD((void), activateEncryption, (), (override));

    MOCK_METHOD((void), deactivateEncryption, (), (override));

    MOCK_METHOD(
        (bool),
        isCardSessionMacValid,
        (const std::vector<std::uint8_t>&),
        (override));

    MOCK_METHOD(
        (void),
        computeSvCommandSecurityData,
        (const std::shared_ptr<SvCommandSecurityDataApi>),
        (override));

    MOCK_METHOD(
        (bool),
        isCardSvMacValid,
        (const std::vector<std::uint8_t>&),
        (override));

    MOCK_METHOD(
        (std::vector<std::uint8_t>),
        cipherPinForPresentation,
        (const std::vector<std::uint8_t>&,
         const std::vector<std::uint8_t>&,
         const std::shared_ptr<std::uint8_t>,
         const std::shared_ptr<std::uint8_t>),
        (override));

    MOCK_METHOD(
        (std::vector<std::uint8_t>),
        cipherPinForModification,
        (const std::vector<std::uint8_t>&,
         const std::vector<std::uint8_t>&,
         const std::vector<std::uint8_t>&,
         const std::shared_ptr<std::uint8_t>,
         const std::shared_ptr<std::uint8_t>),
        (override));

    MOCK_METHOD(
        (std::vector<std::uint8_t>),
        generateCipheredCardKey,
        (const std::vector<std::uint8_t>&,
         const std::uint8_t,
         const std::uint8_t,
         const std::uint8_t,
         const std::uint8_t targetKeyKvc),
        (override));

    MOCK_METHOD((void), synchronize, (), (override));
};
