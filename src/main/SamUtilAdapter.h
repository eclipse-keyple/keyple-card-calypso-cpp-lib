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

/* Calypsonet Terminal Calypso */
#include "CalypsoSam.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::sam;

using ProductType = CalypsoSam::ProductType;

/**
 * (package-private)<br>
 */
class SamUtilAdapter final {
public:
    /**
     * (package-private)<br>
     * Get the class byte to use for the provided product type.
     *
     * @param productType The SAM product type.
     * @return A byte.
     * @since 2.0.0
     */
    static uint8_t getClassByte(const ProductType productType);

private:
    /**
     * Constructor
     */
    SamUtilAdapter();
};

}
}
}
