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
#include "BasicSignatureVerificationData.h"

/* Keyple Card Calypso */
#include "CommonSignatureVerificationDataAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::transaction;

/**
 * (package-private)<br>
 * Implementation of BasicSignatureVerificationData.
 *
 * @since 2.2.0
 */
class BasicSignatureVerificationDataAdapter final
: public CommonSignatureVerificationDataAdapter<BasicSignatureVerificationData>,
  public BasicSignatureVerificationData {};

}
}
}
