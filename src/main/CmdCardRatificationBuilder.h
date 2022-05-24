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

#pragma once

/* Keyple Card Calypso */
#include "ApduRequestAdapter.h"
#include "CalypsoCardClass.h"

namespace keyple {
namespace card {
namespace calypso {

/**
 * (package-private)<br>
 * Provides the ApduRequestAdapter dedicated to the ratification command.
 *
 * <p>i.e. the command sent after closing the secure session to handle the ratification mechanism.
 * <br>
 * This particular command is not associated with any parsing since the response to this command is
 * always an error and is never checked.
 *
 * @since 2.0.1
 */
class CmdCardRatificationBuilder final {
public:
    /**
     * (package-private)<br>
     *
     * @param calypsoCardClass the card class.
     * @return the ApduRequestAdapter ratification command according to the card class provided
     * @since 2.0.1
     */
    static const std::shared_ptr<ApduRequestAdapter> getApduRequest(
        const CalypsoCardClass calypsoCardClass);

private:
    /**
     * (private)<br>
     * Hidden constructor.
     */
    CmdCardRatificationBuilder();
};

}
}
}
