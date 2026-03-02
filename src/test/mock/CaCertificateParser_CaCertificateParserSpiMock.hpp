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
#include "keypop/calypso/crypto/asymmetric/certificate/spi/CaCertificateParserSpi.hpp"
#include "keypop/calypso/crypto/asymmetric/certificate/spi/CaCertificateSpi.hpp"
#include "keypop/calypso/crypto/asymmetric/certificate/spi/cpp/PublicKey.hpp"

using keypop::calypso::card::transaction::spi::CaCertificateParser;
using keypop::calypso::crypto::asymmetric::certificate::spi::
    CaCertificateParserSpi;
using keypop::calypso::crypto::asymmetric::certificate::spi::CaCertificateSpi;
using keypop::calypso::crypto::asymmetric::certificate::spi::cpp::PublicKey;

class CaCertificateParser_CaCertificateParserSpiMock final
: public CaCertificateParserSpi,
  public CaCertificateParser {
public:
    CaCertificateParser_CaCertificateParserSpiMock() = default;

    ~CaCertificateParser_CaCertificateParserSpiMock() = default;

    MOCK_METHOD((std::uint8_t), getCertificateType, (), (const, override));

    MOCK_METHOD(
        (std::shared_ptr<CaCertificateSpi>),
        parseCertificate,
        (const std::vector<uint8_t>&),
        (const, override));
};
