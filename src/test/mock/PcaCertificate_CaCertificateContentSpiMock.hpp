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
#include <vector>

#include "keypop/calypso/card/transaction/spi/PcaCertificate.hpp"
#include "keypop/calypso/crypto/asymmetric/certificate/spi/CaCertificateContentSpi.hpp"
#include "keypop/calypso/crypto/asymmetric/certificate/spi/cpp/PublicKey.hpp"

using keypop::calypso::card::transaction::spi::PcaCertificate;
using keypop::calypso::crypto::asymmetric::certificate::spi::
    CaCertificateContentSpi;
using keypop::calypso::crypto::asymmetric::certificate::spi::cpp::PublicKey;

class PcaCertificate_CaCertificateContentSpiMock final
: public CaCertificateContentSpi,
  public PcaCertificate {
public:
    PcaCertificate_CaCertificateContentSpiMock() = default;

    ~PcaCertificate_CaCertificateContentSpiMock() = default;

    MOCK_METHOD(
        (const std::shared_ptr<PublicKey>),
        getPublicKey,
        (),
        (const, override));

    MOCK_METHOD(
        (const std::vector<uint8_t>&),
        getPublicKeyReference,
        (),
        (const, override));

    MOCK_METHOD((uint64_t), getStartDate, (), (const, override));

    MOCK_METHOD((uint64_t), getEndDate, (), (const, override));

    MOCK_METHOD((bool), isAidCheckRequested, (), (const, override));

    MOCK_METHOD((bool), isAidTruncated, (), (const, override));

    MOCK_METHOD((const std::vector<uint8_t>&), getAid, (), (const, override));

    MOCK_METHOD(
        (bool), isCaCertificatesAuthenticationAllowed, (), (const, override));

    MOCK_METHOD(
        (bool), isCardCertificatesAuthenticationAllowed, (), (const, override));
};
