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

#include <cstdint>
#include <map>
#include <memory>
#include <vector>

/* Calypsonet Terminal Calypso */
#include "DirectoryHeader.h"
#include "WriteAccessLevel.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso;
using namespace calypsonet::terminal::calypso::card;

/**
 * (package-private)<br>
 * Implementation of DirectoryHeader.
 *
 * @since 2.0.0
 */
class DirectoryHeaderAdapter final : public DirectoryHeader {
public:
    /**
     * (package-private)<br>
     * CalypsoSamCardSelectorBuilder pattern
     *
     * @since 2.0.0
     */
    class DirectoryHeaderBuilder final
    : public std::enable_shared_from_this<DirectoryHeaderBuilder> {
    public:
        /**
         *
         */
        friend class DirectoryHeaderAdapter;

        /**
         * (package-private)<br>
         * Sets the LID.
         *
         * @param lid the LID.
         * @return the builder instance
         * @since 2.0.0
         */
        DirectoryHeaderBuilder& lid(const uint16_t lid);

        /**
         * (package-private)<br>
         * Sets a reference to the provided access conditions byte array.
         *
         * @param accessConditions the access conditions (should be not null and 4 bytes length).
         * @return the builder instance
         * @since 2.0.0
         */
        DirectoryHeaderBuilder& accessConditions(const std::vector<uint8_t>& accessConditions);

        /**
         * (package-private)<br>
         * Sets a reference to the provided key indexes byte array.
         *
         * @param keyIndexes the key indexes (should be not null and 4 bytes length).
         * @return the builder instance
         * @since 2.0.0
         */
        DirectoryHeaderBuilder& keyIndexes(const std::vector<uint8_t>& keyIndexes);

        /**
         * (package-private)<br>
         * Sets the DF status.
         *
         * @param dfStatus the DF status (byte).
         * @return the builder instance
         * @since 2.0.0
         */
        DirectoryHeaderBuilder& dfStatus(const uint8_t dfStatus);

        /**
         * (package-private)<br>
         * Add a KIF.
         *
         * @param level the KIF session access level (should be not null).
         * @param kif the KIF value.
         * @return the builder instance
         * @since 2.0.0
         */
        DirectoryHeaderBuilder& kif(const WriteAccessLevel level, const uint8_t kif);

        /**
         * (package-private)<br>
         * Add a KVC.
         *
         * @param level the KVC session access level (should be not null).
         * @param kvc the KVC value.
         * @return the builder instance
         * @since 2.0.0
         */
        DirectoryHeaderBuilder& kvc(const WriteAccessLevel level, const uint8_t kvc);

        /**
         * (package-private)<br>
         * Build a new {@code DirectoryHeader}.
         *
         * @return a new instance
         * @since 2.0.0
         */
        const std::shared_ptr<DirectoryHeader> build();

        /**
         *
         */
        friend class DirectoryHeaderAdapter;

    private:
        /**
         *
         */
        uint16_t mLid;

        /**
         *
         */
        std::vector<uint8_t> mAccessConditions;

        /**
         *
         */
        std::vector<uint8_t> mKeyIndexes;

        /**
         *
         */
        uint8_t mDfStatus;

        /**
         *
         */
        std::map<const WriteAccessLevel, const uint8_t> mKif;

        /**
         *
         */
        std::map<const WriteAccessLevel, const uint8_t> mKvc;

        /**
         * Private constructor
         */
        DirectoryHeaderBuilder();

    };

    /**
     *
     */
    uint16_t getLid() const override;

    /**
     *
     */
    const std::vector<uint8_t>& getAccessConditions() const override;

    /**
     *
     */
    const std::vector<uint8_t>& getKeyIndexes() const override;

    /**
     *
     */
    uint8_t getDfStatus() const override;

    /**
     *
     */
    uint8_t getKif(const WriteAccessLevel writeAccessLevel) const override;

    /**
     *
     */
    uint8_t getKvc(const WriteAccessLevel writeAccessLevel) const override;

    /**
     * (package-private)<br>
     * Gets a new builder.
     *
     * @return a new builder instance
     * @since 2.0.0
     */
    static std::shared_ptr<DirectoryHeaderBuilder> builder();

private:
    /**
     *
     */
    const uint16_t mLid;

    /**
     *
     */
    const std::vector<uint8_t> mAccessConditions;

    /**
     *
     */
    const std::vector<uint8_t> mKeyIndexes;

    /**
     *
     */
    const uint8_t mDfStatus;

    /**
     *
     */
    const std::map<const WriteAccessLevel, const uint8_t> mKif;

    /**
     *
     */
    const std::map<const WriteAccessLevel, const uint8_t> mKvc;

    /**
     *
     */
    static const std::string LEVEL_STR;

    /**
     * Private constructor
     */
    DirectoryHeaderAdapter(const std::shared_ptr<DirectoryHeaderBuilder> builder);
};

}
}
}
