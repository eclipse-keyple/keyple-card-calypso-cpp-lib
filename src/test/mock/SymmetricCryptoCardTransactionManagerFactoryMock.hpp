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

#include "keypop/calypso/card/transaction/spi/SymmetricCryptoCardTransactionManagerFactory.hpp"
#include "keypop/calypso/crypto/symmetric/spi/SymmetricCryptoCardTransactionManagerFactorySpi.hpp"
#include "keypop/calypso/crypto/symmetric/spi/SymmetricCryptoCardTransactionManagerSpi.hpp"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using keypop::calypso::card::transaction::spi::
    SymmetricCryptoCardTransactionManagerFactory;
using keypop::calypso::crypto::symmetric::spi::
    SymmetricCryptoCardTransactionManagerFactorySpi;
using keypop::calypso::crypto::symmetric::spi::
    SymmetricCryptoCardTransactionManagerSpi;

class SymmetricCryptoCardTransactionManagerFactoryMock final
: public SymmetricCryptoCardTransactionManagerFactory,
  public SymmetricCryptoCardTransactionManagerFactorySpi {
public:
    SymmetricCryptoCardTransactionManagerFactoryMock() = default;

    ~SymmetricCryptoCardTransactionManagerFactoryMock() = default;

    MOCK_METHOD((bool), isExtendedModeSupported, (), (const, override));

    MOCK_METHOD((int), getMaxCardApduLengthSupported, (), (const, override));

    MOCK_METHOD((void), preInitTerminalSessionContext, (), (override));

    MOCK_METHOD(
        (std::shared_ptr<SymmetricCryptoCardTransactionManagerSpi>),
        createCardTransactionManager,
        (const std::vector<uint8_t>&,
         const bool,
         const std::vector<std::vector<uint8_t>>&),
        (override));
};
