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

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

/* Keyple Card Calypso */
#include "AbstractApduCommand.h"
#include "AbstractCardCommand.h"
#include "CalypsoCardCommand.h"
#include "CalypsoCardClass.h"
#include "FileHeaderAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

using StatusProperties = AbstractApduCommand::StatusProperties;

/**
 * (package-private)<br>
 * Builds the Get data APDU commands for the EF LIST tag.
 *
 * <p>In contact mode, this command can not be sent in a secure session because it would generate a
 * 6Cxx status and thus make calculation of the digest impossible.
 *
 * @since 2.1.0
 */
class CmdCardGetDataEfList final : public AbstractCardCommand {
public:
    /**
     * (package-private)<br>
     * Instantiates a new CmdCardGetDataEfList.
     *
     * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
     * @since 2.1.0
     */
    CmdCardGetDataEfList(const CalypsoCardClass calypsoCardClass);

    /**
     * {@inheritDoc}
     *
     * @return False
     * @since 2.1.0
     */
    bool isSessionBufferUsed() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    const std::map<const int, const std::shared_ptr<StatusProperties>>& getStatusTable() const
        override;

    /**
     * (package-private)<br>
     * Gets a reference to a map of all Elementary File headers and their associated SFI.
     *
     * @return A not empty map.
     * @since 2.1.0
     */
    const std::map<const std::shared_ptr<FileHeaderAdapter>, const uint8_t> getEfHeaders() const;

private:
    /**
     *
     */
    static const CalypsoCardCommand mCommand;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> STATUS_TABLE;

    /**
     *
     */
    static const int DESCRIPTORS_OFFSET;
    static const int DESCRIPTOR_DATA_OFFSET;
    static const int DESCRIPTOR_DATA_SFI_OFFSET;
    static const int DESCRIPTOR_TAG_LENGTH;
    static const int DESCRIPTOR_DATA_LENGTH;

    /**
     * (private) Creates a FileHeader from a 6-byte descriptor as defined by the GET DATA
     * command for the tag EF LIST.
     *
     * @param efDescriptorByteArray A 6-byte array.
     * @return A not null FileHeader.
     */
    const std::shared_ptr<FileHeaderAdapter> createFileHeader(
        const std::vector<uint8_t>& efDescriptorByteArray) const;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
