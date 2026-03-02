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

#pragma once

#include <random>
#include <vector>

namespace keyple {
namespace card {
namespace calypso {
namespace cpp {

/**
 * C++ SecureRandom implementation
 */
class SecureRandom {
public:
    /**
     * Constructor.
     */
    SecureRandom();

    /**
     * Reseeds this random object, using the eight bytes contained in the given
     * long seed. The given seed supplements, rather than replaces, the existing
     * seed. Thus, repeated calls are guaranteed never to reduce randomness.
     */
    void setSeed();

    /**
     * Generates a user-specified number of random bytes.
     *
     * If a call to setSeed had not occurred previously, the first call to this
     * method forces this SecureRandom object to seed itself. This self-seeding
     * will not occur if setSeed was previously called.
     */
    void nextBytes(std::vector<std::uint8_t>& bytes);

private:
    /**
     * Seeded flag.
     */
    bool mSeeded;

    /**
     * Random generator.
     */
    std::mt19937 mGen;

    /**
     * Random distribution.
     */
    std::uniform_int_distribution<int> mDist;
};

} /* namespace cpp */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
