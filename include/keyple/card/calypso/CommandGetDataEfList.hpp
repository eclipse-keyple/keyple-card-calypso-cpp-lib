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
#include "keyple/card/calypso/FileHeaderAdapter.hpp"

namespace keyple {
namespace card {
namespace calypso {

/**
 * Builds the Get data APDU commands for the EF LIST tag.
 *
 * <p>In contact mode, this command can not be sent in a secure session because
 * it would generate a 6Cxx status and thus make calculation of the digest
 * impossible.
 *
 * @since 2.1.0
 */
class CommandGetDataEfList final : public Command {
public:
    /**
     * Constructor.
     *
     * @param transactionContext The global transaction context common to all
     * commands.
     * @param commandContext The local command context specific to each command.
     * @since 2.3.2
     */
    CommandGetDataEfList(
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
     * @since 2.3.2
     */
    void parseResponse(std::shared_ptr<ApduResponseApi> apduResponse) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
    getStatusTable() const override;

private:
    /** */
    static const int DESCRIPTORS_OFFSET;
    static const int DESCRIPTOR_DATA_OFFSET;
    static const int DESCRIPTOR_DATA_SFI_OFFSET;
    static const int DESCRIPTOR_TAG_LENGTH;
    static const int DESCRIPTOR_DATA_LENGTH;

    /**
     *
     */
    static const std::map<int, const std::shared_ptr<Command::StatusProperties>>
        STATUS_TABLE;

    /**
     * Gets a reference to a map of all Elementary File headers and their
     * associated SFI.
     *
     * @return A not empty map.
     * @since 2.1.0
     */
    std::map<std::shared_ptr<FileHeaderAdapter>, std::uint8_t> getEfHeaders();

    /**
     * Creates a FileHeader from a 6-byte descriptor as defined by the
     * GET DATA command for the tag EF LIST.
     *
     * @param efDescriptorByteArray A 6-byte array.
     * @return A not null {@link FileHeader}.
     */
    static std::shared_ptr<FileHeaderAdapter>
    createFileHeader(const std::vector<std::uint8_t>& efDescriptorByteArray);
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
