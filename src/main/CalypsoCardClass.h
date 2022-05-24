/**************************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/                        *
 *                                                                                                *
 * See the NOTICE file(s) distributed with this work for additional information regarding         *
 * copyright ownership.                                                                           *
 *                                                                                                *
 * This program and the accompanying materials are made available under the terms of the Eclipse  *
 * Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0                  *
 *                                                                                                *
 * SPDX-License-Identifier: EPL-2.0                                                               *
 **************************************************************************************************/

#pragma once

#include <cstdint>
#include <ostream>

namespace keyple {
namespace card {
namespace calypso {

/**
 * (package-private)<br>
 * Defines the two existing ISO7816 class bytes for a Calypso card command.: LEGACY for REV1 /
 * BPRIME type card, ISO for REV2/3 / B type
 *
 * @since 2.0.0
 */
class CalypsoCardClass {
public:
    /** Dummy init value */
    static const CalypsoCardClass UNKNOWN;

    /** Calypso product type 1/2 / B Prime protocol, regular commands */
    static const CalypsoCardClass LEGACY;

    /** Calypso product type 1/2 / B Prime protocol, Stored Value commands */
    static const CalypsoCardClass LEGACY_STORED_VALUE;

    /** Calypso product type 3 and higher */
    static const CalypsoCardClass ISO;

    /**
     *
     */
    CalypsoCardClass(const CalypsoCardClass& o);

    /**
     * Gets the class byte.
     *
     * @return A byte
     * @since 2.0.0
     */
    uint8_t getValue() const;

    /**
     *
     */
    CalypsoCardClass& operator=(const CalypsoCardClass& o);

    /**
     *
     */
    bool operator==(const CalypsoCardClass& o) const;

    /**
     *
     */
    friend std::ostream& operator<<(std::ostream& os, const CalypsoCardClass& ccc);

private:
    /**
     *
     */
    uint8_t mCla;

    /**
     * Constructor
     *
     * @param cla class byte value.
     */
    CalypsoCardClass(const uint8_t cla);
};

}
}
}
