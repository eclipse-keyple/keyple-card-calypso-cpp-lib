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
#include <string>

/* Keyple Card Calypso */
#include "ApduRequestAdapter.h"
#include "CalypsoApduCommandException.h"
#include "CardCommand.h"

/* Calypsonet Terminal Card */
#include "ApduResponseApi.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::card;

/**
 * (package-private)<br>
 * Generic APDU command.
 *
 * <p>It provides the generic getters to retrieve:
 *
 * <ul>
 *   <li>the card command reference,
 *   <li>the name of the command,
 *   <li>the built {@link org.calypsonet.terminal.card.spi.ApduRequestSpi},
 *   <li>the parsed {@link org.calypsonet.terminal.card.ApduResponseApi}.
 * </ul>
 *
 * @since 2.0.1
 */
class AbstractApduCommand {
public:
    /**
     * (package-private)<br>
     * This internal class provides status word properties
     *
     * @since 2.0.1
     */
    class StatusProperties {
    public:
        /**
         * (package-private)<br>
         * Creates a successful status.
         *
         * @param information the status information.
         * @since 2.0.1
         */
        StatusProperties(const std::string& information);

        /**
         * (package-private)<br>
         * Creates an error status.<br>
         * If {@code exceptionClass} is null, then a successful status is created.
         *
         * @param information the status information.
         * @param exceptionClass the associated exception class.
         * @since 2.0.1
         */
        StatusProperties(const std::string& information, const std::type_info& exceptionClass);

        /**
         * (package-private)<br>
         * Gets information
         *
         * @return A nullable reference
         * @since 2.0.1
         */
        const std::string& getInformation() const;

        /**
         * (package-private)<br>
         * Gets successful indicator
         *
         * @return The successful indicator;
         * @since 2.0.1
         */
        bool isSuccessful() const;

        /**
         * (package-private)<br>
         * Gets Exception Class
         *
         * @return A nullable reference
         * @since 2.0.1
         */
        const std::type_info& getExceptionClass() const;

    private:
        /**
         *
         */
        const std::string mInformation;

        /**
         *
         */
        const bool mSuccessful;

        /**
         *
         */
        const std::type_info& mExceptionClass;
    };

    /**
     * (package-private)<br>
     * This Map stores expected status that could be by default initialized with sw1=90 and sw2=00
     * (Success)
     *
     * @since 2.0.1
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> STATUS_TABLE;

    /**
     * (package-private)<br>
     * Constructor
     *
     * @param commandRef The command reference.
     * @since 2.0.1
     */
    AbstractApduCommand(const CardCommand& commandRef);

    /**
     * (package-private)<br>
     * Appends a string to the current name.
     *
     * <p>The sub name completes the name of the current command. This method must therefore only be
     * invoked conditionally (log level &gt;= debug).
     *
     * @param subName The string to append.
     * @throws NullPointerException If the request is not set.
     * @since 2.0.1
     */
    virtual void addSubName(const std::string& subName) final;

    /**
     * (package-private)<br>
     * Gets CardCommand the current command identification
     *
     * @return A not null reference.
     * @since 2.0.1
     */
    virtual const CardCommand& getCommandRef() const;

    /**
     * (package-private)<br>
     * Gets the name of this APDU command.
     *
     * @return A not empty string.
     * @since 2.0.1
     */
    virtual const std::string& getName() const final;

    /**
     * (package-private)<br>
     * Sets the command {@link ApduRequestAdapter}.
     *
     * @param apduRequest The APDU request.
     * @since 2.0.1
     */
    virtual void setApduRequest(const std::shared_ptr<ApduRequestAdapter> apduRequest) final;

    /**
     * (package-private)<br>
     * Gets the {@link ApduRequestAdapter}.
     *
     * @return Null if the request is not set.
     * @since 2.0.1
     */
    virtual const std::shared_ptr<ApduRequestAdapter> getApduRequest() const final;

    /**
     * (package-private)<br>
     * Sets the command {@link ApduResponseApi}.
     *
     * @param apduResponse The APDU response.
     * @return The current instance.
     * @since 2.0.1
     */
    virtual AbstractApduCommand& setApduResponse(
        const std::shared_ptr<ApduResponseApi> apduResponse);

    /**
     * (package-private)<br>
     * Gets {@link ApduResponseApi}
     *
     * @return Null if the response is not set.
     * @since 2.0.1
     */
    virtual const std::shared_ptr<ApduResponseApi> getApduResponse() const final;

    /**
     * (package-private)<br>
     * Returns the internal status table
     *
     * @return A not null reference
     * @since 2.0.1
     */
    virtual const std::map<const int, const std::shared_ptr<StatusProperties>>& getStatusTable()
        const;

    /**
     * (package-private)<br>
     * Builds a command exception.
     *
     * <p>This method should be override in subclasses in order to create specific exceptions.
     *
     * @param exceptionClass the exception class.
     * @param message the message.
     * @param commandRef CardCommand the command reference.
     * @param statusWord the status word.
     * @return A not null value
     * @since 2.0.1
     */
    virtual const CalypsoApduCommandException buildCommandException(
        const std::type_info& exceptionClass,
        const std::string& message,
        const CardCommand& commandRef,
        const int statusWord) const;

    /**
     * (package-private)<br>
     * Gets true if the status is successful from the statusTable according to the current status
     * code.
     *
     * @return A value
     * @since 2.0.1
     */
    virtual bool isSuccessful() const final;

    /**
     * (package-private)<br>
     * This method check the status word.<br>
     * If status word is not referenced, then status is considered unsuccessful.
     *
     * @throws CalypsoApduCommandException if status is not successful.
     * @since 2.0.1
     */
    virtual void checkStatus();

    /**
     * (package-private)<br>
     * Gets the ASCII message from the statusTable for the current status word.
     *
     * @return A nullable value
     * @since 2.0.1
     */
    virtual const std::string getStatusInformation() const final;

private:
    /**
     *
     */
    const CardCommand& mCommandRef;

    /**
     *
     */
    std::string mName;

    /**
     *
     */
    std::shared_ptr<ApduRequestAdapter> mApduRequest;

    /**
     *
     */
    std::shared_ptr<ApduResponseApi> mApduResponse;

    /**
     * (private)<br>
     *
     * @return The properties of the result.
     * @throws NullPointerException If the response is not set.
     */
    virtual const std::shared_ptr<StatusProperties> getStatusWordProperties() const;
};

}
}
}
