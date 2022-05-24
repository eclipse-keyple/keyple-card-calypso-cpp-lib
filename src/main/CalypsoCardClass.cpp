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

#include "CalypsoCardClass.h"

namespace keyple {
namespace card {
namespace calypso {

const CalypsoCardClass CalypsoCardClass::LEGACY(0x94);
const CalypsoCardClass CalypsoCardClass::LEGACY_STORED_VALUE(0xFA);
const CalypsoCardClass CalypsoCardClass::ISO(0x00);
const CalypsoCardClass CalypsoCardClass::UNKNOWN(0xff);

CalypsoCardClass::CalypsoCardClass(const uint8_t cla) : mCla(cla) {}

CalypsoCardClass::CalypsoCardClass(const CalypsoCardClass& o) : CalypsoCardClass(o.mCla) {}

uint8_t CalypsoCardClass::getValue() const
{
    return mCla;
}

CalypsoCardClass& CalypsoCardClass::operator=(const CalypsoCardClass& o)
{
    mCla = o.mCla;

    return *this;
}

bool CalypsoCardClass::operator==(const CalypsoCardClass& o) const
{
    return mCla == o.mCla;
}

std::ostream& operator<<(std::ostream& os, const CalypsoCardClass& ccc)
{
    os << "CALYPSO_CARD_CLASS: ";

    if (ccc.getValue() == CalypsoCardClass::ISO.getValue()) {
        os << "ISO";
    } else if (ccc.getValue() == CalypsoCardClass::LEGACY.getValue()) {
        os << "LEGACY";
    } else if (ccc.getValue() == CalypsoCardClass::LEGACY_STORED_VALUE.getValue()) {
        os << "LEGACY_STORED_VALUE";
    } else {
        os << "UNKNOWN";
    }

    return os;
}

}
}
}
