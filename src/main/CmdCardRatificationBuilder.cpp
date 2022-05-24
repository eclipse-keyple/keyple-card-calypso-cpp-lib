/**************************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/                        *
 *                                                                                                *
 * See the NOTICE file(s) distributed with this work for additional information regarding         *
 * copyright ownership.                                                                           *
 *                                                                                                *
 * This program and the accompanying materials are made available under the terms of the Eclipse  *
 * Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0                  *
 *                                                                                                *
 * SPDX-License-Identifier: EPL-2.0                                                               *
 **************************************************************************************************/

#include "CmdCardRatificationBuilder.h"

namespace keyple {
namespace card {
namespace calypso {

CmdCardRatificationBuilder::CmdCardRatificationBuilder() {}

const std::shared_ptr<ApduRequestAdapter> CmdCardRatificationBuilder::getApduRequest(
    const CalypsoCardClass calypsoCardClass)
{
    const std::vector<uint8_t> ratificationApdu = {
        calypsoCardClass.getValue(), 0xB2, 0x00, 0x00, 0x00
    };

    return std::make_shared<ApduRequestAdapter>(ratificationApdu);
}

}
}
}
