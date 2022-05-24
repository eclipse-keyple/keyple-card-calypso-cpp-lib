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

#include "SamUtilAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

SamUtilAdapter::SamUtilAdapter() {}

uint8_t SamUtilAdapter::getClassByte(const ProductType productType)
{
    if (productType == ProductType::SAM_S1DX) {
        return 0x94;
    }
        return 0x80;
    }

}
}
}
