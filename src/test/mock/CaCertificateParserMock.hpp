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

#include <cstdint>
#include <memory>
#include <vector>

#include "keypop/calypso/card/transaction/spi/CaCertificateParser.hpp"
#include "keypop/calypso/crypto/asymmetric/certificate/spi/CaCertificateSpi.hpp"

using keypop::calypso::card::transaction::spi::CaCertificateParser;
using keypop::calypso::crypto::asymmetric::certificate::spi::CaCertificateSpi;

class CaCertificateParserMock final : public CaCertificateParser {
public:
    CaCertificateParserMock() = default;

    ~CaCertificateParserMock() = default;
};
