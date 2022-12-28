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
#include <map>
#include <ostream>
#include <vector>

/* Calypsonet Terminal Calypso */
#include "CalypsoSam.h"

/* Keyple Card Calypso */
#include "AbstractSamCommand.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::sam;

/**
 * (package-private)<br>
 * Builds the Read Key Parameters APDU command.
 *
 * @since 2.0.1
 */
class CmdSamReadKeyParameters final : public AbstractSamCommand {
public:
    /**
     * Source reference
     */
    enum class SourceRef {
        /**
         * Work key
         */
        WORK_KEY,
        
        /**
         * System key
         */
        SYSTEM_KEY
    };

    /**
     * Navigation control
     */
    enum class NavControl {
        /**
         * First
         */
        FIRST,
        
        /**
         * Next
         */
        NEXT
    };

    /**
     * (package-private)<br>
     * Instantiates a new CmdSamReadKeyParameters for the null key.
     *
     * @param productType the SAM product type.
     * @since 2.0.1
     */
    CmdSamReadKeyParameters(const CalypsoSam::ProductType productType);

    /**
     * (package-private)<br>
     * Instantiates a new CmdSamReadKeyParameters for the provided kif.
     *
     * @param productType the SAM product type.
     * @param kif the kif
     * @since 2.0.1
     */
    CmdSamReadKeyParameters(const CalypsoSam::ProductType productType, const uint8_t kif);

    /**
     * (package-private)<br>
     * Instantiates a new CmdSamReadKeyParameters for the provided kif and kvc.
     *
     * @param productType the SAM product type.
     * @param kif the kif
     * @param kvc the kvc
     * @since 2.0.1
     */
    CmdSamReadKeyParameters(const CalypsoSam::ProductType productType, 
                            const uint8_t kif, 
                            const uint8_t kvc);

    /**
     * (package-private)<br>
     * Instantiates a new CmdSamReadKeyParameters for the provided key reference and record number.
     *
     * @param productType the SAM product type.
     * @param sourceKeyRef the source key reference
     * @param recordNumber the record number
     * @since 2.0.1
     */
    CmdSamReadKeyParameters(const CalypsoSam::ProductType productType, 
                            const SourceRef sourceKeyRef, 
                            const int recordNumber);

    /**
     * (package-private)<br>
     * Instantiates a new CmdSamReadKeyParameters for the provided kif and navigation control flag.
     *
     * @param productType the SAM product type.
     * @param kif the kif
     * @param navControl the navigation control flag
     * @since 2.0.1
     */
    CmdSamReadKeyParameters(const CalypsoSam::ProductType productType, 
                            const uint8_t kif, 
                            const NavControl navControl);

    /**
     * (package-private)<br>
     * Gets the key parameters.
     *
     * @return The key parameters
     * @since 2.0.1
     */
    const std::vector<uint8_t> getKeyParameters() const;

    /**
     * 
     */
    friend std::ostream& operator<<(std::ostream& os, const SourceRef& sr);
    /**
     * 
     */
    friend std::ostream& operator<<(std::ostream& os, const NavControl& nc);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const std::map<const int, const std::shared_ptr<StatusProperties>>& getStatusTable() const
        override;

private:
    /**
     * The command
     */
    static const CalypsoSamCommand mCommand;

    /**
     * 
     */
    static const int MAX_WORK_KEY_REC_NUMB;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> STATUS_TABLE;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
