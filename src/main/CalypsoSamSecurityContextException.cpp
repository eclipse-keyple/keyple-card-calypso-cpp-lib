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

/* Keyple Card Calypso */
#include "CalypsoSamSecurityContextException.h"

namespace keyple {
namespace card {
namespace calypso {

CalypsoSamSecurityContextException::CalypsoSamSecurityContextException(
  const std::string& message, 
  const CalypsoSamCommand& command, 
  const std::shared_ptr<int> statusWord)
: CalypsoSamCommandException(message, command, statusWord) {}


}
}
}
