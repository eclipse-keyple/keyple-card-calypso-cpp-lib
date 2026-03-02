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

#include "keypop/calypso/card/transaction/spi/CardCertificateParser.hpp"
#include "keypop/calypso/crypto/asymmetric/certificate/spi/CardCertificateParserSpi.hpp"
#include "keypop/calypso/crypto/asymmetric/certificate/spi/CardCertificateSpi.hpp"
#include "keypop/calypso/crypto/asymmetric/certificate/spi/cpp/PublicKey.hpp"

using keypop::calypso::card::transaction::spi::CardCertificateParser;
using keypop::calypso::crypto::asymmetric::certificate::spi::
    CardCertificateParserSpi;
using keypop::calypso::crypto::asymmetric::certificate::spi::CardCertificateSpi;
using keypop::calypso::crypto::asymmetric::certificate::spi::cpp::PublicKey;

class CardCertificateParser_CardCertificateParserSpiMock final
: public CardCertificateParserSpi,
  public CardCertificateParser {
public:
    CardCertificateParser_CardCertificateParserSpiMock() = default;

    ~CardCertificateParser_CardCertificateParserSpiMock() = default;

    MOCK_METHOD((std::uint8_t), getCertificateType, (), (const, override));

    MOCK_METHOD(
        (std::shared_ptr<CardCertificateSpi>),
        parseCertificate,
        (const std::vector<uint8_t>&),
        (const, override));
};
