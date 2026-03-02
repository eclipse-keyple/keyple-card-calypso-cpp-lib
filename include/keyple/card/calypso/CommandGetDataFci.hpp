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

#include <map>
#include <memory>
#include <typeinfo>
#include <vector>

#include "keyple/card/calypso/Command.hpp"
#include "keyple/card/calypso/DtoAdapters.hpp"
#include "keyple/core/util/cpp/Logger.hpp"
#include "keyple/core/util/cpp/LoggerFactory.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::cpp::Logger;
using keyple::core::util::cpp::LoggerFactory;

/**
 * Builds the Get data APDU commands for the FCI tag.
 *
 * <p>In contact mode, this command can not be sent in a secure session because
 * it would generate a 6Cxx status and thus make calculation of the digest
 * impossible.
 *
 * @since 2.0.1
 */
class CommandGetDataFci final
: public Command,
  public std::enable_shared_from_this<CommandGetDataFci> {
public:
    /**
     * Constructor.
     *
     * @param transactionContext The global transaction context common to all
     * commands.
     * @param commandContext The local command context specific to each command.
     * @since 2.3.2
     */
    CommandGetDataFci(
        const std::shared_ptr<DtoAdapters::TransactionContextDto>&
            transactionContext,
        const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext);

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    void finalizeRequest() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    bool isCryptoServiceRequiredToFinalizeRequest() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    bool synchronizeCryptoServiceBeforeCardProcessing() override;

    /**
     * {@inheritDoc}
     *
     * <p>The expected FCI structure of a Calypso card follows this scheme:
     * <code>
     * T=6F L=XX (C)    FCI Template
     * T=84 L=XX (P)    DF Name
     * T=A5 L=22 (C)    FCI Proprietary Template
     * T=BF0C L=19 (C)  FCI Issuer Discretionary Data
     * T=C7 L=8 (P)     Application Serial Number
     * T=53 L=7 (P)     Discretionary Data (Startup Information)
     * </code>
     *
     * <p>The ApduResponseApi provided in argument is parsed according to the
     * above expected structure.
     *
     * <p>DF Name, Application Serial Number and Startup Information are
     * extracted.
     *
     * <p>The 7-byte startup information field is also split into 7 private
     * field made available through dedicated getter methods.
     *
     * <p>All fields are pre-initialized to handle the case where the parsing
     * fails.
     *
     * @since 2.3.2
     */
    void parseResponse(std::shared_ptr<ApduResponseApi> apduResponse) override;

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
    const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
    getStatusTable() const override;

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger
        = LoggerFactory::getLogger(typeid(CommandGetDataFci));

    /**
     *
     */
    static const std::map<int, const std::shared_ptr<Command::StatusProperties>>
        STATUS_TABLE;

    /**
     * BER-TLV tags definitions
     */
    static const int TAG_DF_NAME;
    static const int TAG_APPLICATION_SERIAL_NUMBER;
    static const int TAG_DISCRETIONARY_DATA;

    /**
     * Attributes result of th FCI parsing
     */
    bool mIsDfInvalidated = false;

    /**
     *
     */
    bool mIsValidCalypsoFCI = false;

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
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
