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

#include "keyple/card/calypso/crypto/legacysam/LegacySamAdapter.hpp"
#include "keypop/calypso/crypto/asymmetric/transaction/spi/AsymmetricCryptoCardTransactionManagerFactorySpi.hpp"
#include "keypop/calypso/crypto/asymmetric/transaction/spi/AsymmetricCryptoCardTransactionManagerSpi.hpp"
#include "keypop/card/ProxyReaderApi.hpp"

using keyple::card::calypso::crypto::legacysam::LegacySamAdapter;
using keypop::calypso::crypto::asymmetric::transaction::spi::
    AsymmetricCryptoCardTransactionManagerFactorySpi;
using keypop::calypso::crypto::asymmetric::transaction::spi::
    AsymmetricCryptoCardTransactionManagerSpi;
using keypop::card::ProxyReaderApi;

class AsymmetricCryptoCardTransactionManagerFactorySpiMock final
: public AsymmetricCryptoCardTransactionManagerFactorySpi {
public:
    std::shared_ptr<AsymmetricCryptoCardTransactionManagerSpi>
    createCardTransactionManager() const
    {
        return nullptr;
    }
};
