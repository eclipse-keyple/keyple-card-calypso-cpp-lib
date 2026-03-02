/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * See the NOTICE file(s) distributed with this work for additional           *
 * information regarding copyright ownership.                                 *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the Eclipse Public License 2.0 which is available at              *
 * http://www.eclipse.org/legal/epl-2.0                                       *
 *                                                                            *
 * SPDX-License-Identifier: EPL-2.0                                           *
 ******************************************************************************/

#include "keyple/card/calypso/cpp/SecureRandom.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace cpp {

SecureRandom::SecureRandom()
: mSeeded(false)
{
}

void
SecureRandom::setSeed()
{
    std::random_device rd;

    mGen = std::mt19937(rd());
    mDist = std::uniform_int_distribution<int>(0, 255);

    mSeeded = true;
}

void
SecureRandom::nextBytes(std::vector<std::uint8_t>& bytes)
{
    if (!mSeeded) {
        setSeed();
    }

    for (int i = 0; i < static_cast<int>(bytes.size()); i++) {
        bytes[i] = mDist(mGen);
    }
}

} /* namespace cpp */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
