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

#include <map>
#include <memory>
#include <typeinfo>
#include <vector>

/* Keyple Card Calypso */
#include "AbstractApduCommand.h"
#include "AbstractCardCommand.h"
#include "CalypsoCardClass.h"
#include "CalypsoCardCommand.h"

/* Keyple Core Util */
#include "LoggerFactory.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util::cpp;

using StatusProperties = AbstractApduCommand::StatusProperties;

/**
 * (package-private)<br>
 * Builds the Get data APDU commands for the FCI tag.
 *
 * <p>In contact mode, this command can not be sent in a secure session because it would generate a
 * 6Cxx status and thus make calculation of the digest impossible.
 *
 * @since 2.0.1
 */
class CmdCardGetDataFci final : public AbstractCardCommand {
public:
    /**
     * (package-private)<br>
     * Instantiates a new CmdCardGetDataFci.
     *
     * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
     * @since 2.0.1
     */
    CmdCardGetDataFci(const CalypsoCardClass calypsoCardClass);

    /**
     * (package-private)<br>
     * Empty constructor.
     *
     * @since 2.0.1
     */
    CmdCardGetDataFci();

    /**
     * {@inheritDoc}
     *
     * @return False
     * @since 2.0.1
     */
    bool isSessionBufferUsed() const override;

    /**
     * {@inheritDoc}
     *
     * <p>The expected FCI structure of a Calypso card follows this scheme: <code>
     * T=6F L=XX (C)                FCI Template
     *      T=84 L=XX (P)           DF Name
     *      T=A5 L=22 (C)           FCI Proprietary Template
     *           T=BF0C L=19 (C)    FCI Issuer Discretionary Data
     *                T=C7 L=8 (P)  Application Serial Number
     *                T=53 L=7 (P)  Discretionary Data (Startup Information)
     * </code>
     *
     * <p>The ApduResponseApi provided in argument is parsed according to the above expected
     * structure.
     *
     * <p>DF Name, Application Serial Number and Startup Information are extracted.
     *
     * <p>The 7-byte startup information field is also split into 7 private field made available
     * through dedicated getter methods.
     *
     * <p>All fields are pre-initialized to handle the case where the parsing fails.
     *
     * @since 2.0.1
     */
    CmdCardGetDataFci& setApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse)
        override;

    /**
     * (package-private)<br>
     * Tells if the FCI is valid
     *
     * @return True if the FCI is valid, false if not
     * @since 2.0.1
     */
    bool isValidCalypsoFCI() const;

    /**
     * (package-private)<br>
     * Gets the DF name
     *
     * @return An array of bytes
     * @since 2.0.1
     */
    const std::vector<uint8_t>& getDfName() const;

    /**
     * (package-private)<br>
     * Gets the application serial number
     *
     * @return An array of bytes
     * @since 2.0.1
     */
    const std::vector<uint8_t>& getApplicationSerialNumber() const;

    /**
     * (package-private)<br>
     * Gets the discretionary data
     *
     * @return An array of bytes
     * @since 2.0.1
     */
    const std::vector<uint8_t>& getDiscretionaryData() const;

    /**
     * (package-private)<br>
     * Tells if the DF is invalidated
     *
     * @return True if the DF is invalidated, false if not
     * @since 2.0.1
     */
    bool isDfInvalidated() const;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const std::map<const int, const std::shared_ptr<StatusProperties>>& getStatusTable() const
        override;

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger = LoggerFactory::getLogger(typeid(CmdCardGetDataFci));

    /**
     *
     */
    static const CalypsoCardCommand mCommand;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> STATUS_TABLE;

    /**
     * BER-TLV tags definitions
     */
    static const int TAG_DF_NAME;
    static const int TAG_APPLICATION_SERIAL_NUMBER;
    static const int TAG_DISCRETIONARY_DATA;

    /**
     * Attributes result of th FCI parsing
     */
    bool mIsDfInvalidated;
    bool mIsValidCalypsoFCI;

    /**
     *
     */
    std::vector<uint8_t> mDfName;

    /**
     *
     */
    std::vector<uint8_t> mApplicationSN;

    /**
     *
     */
    std::vector<uint8_t> mDiscretionaryData;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
