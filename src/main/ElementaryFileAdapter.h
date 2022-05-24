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
#include <ostream>

/* Calpsonet Terminal Calypso */
#include "ElementaryFile.h"

/* Keyple Card Calypso */
#include "FileDataAdapter.h"
#include "FileHeaderAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::card;

/**
 * (package-private)<br>
 * Implementation of ElementaryFile.
 *
 * @since 2.0.0
 */
class ElementaryFileAdapter final : public ElementaryFile {
public:
    /**
     * (package-private)<br>
     * Constructor
     *
     * @param sfi the associated SFI.
     * @since 2.0.0
     */
    ElementaryFileAdapter(const uint8_t sfi);

    /**
     * (package-private)<br>
     * Constructor used to create a clone of the provided EF.
     *
     * @param source the EF to be cloned.
     * @since 2.0.0
     */
    ElementaryFileAdapter(const std::shared_ptr<ElementaryFile> source);

    /**
     * (package-private)<br>
     * Sets the file header.
     *
     * @param header the file header (should be not null).
     * @return the current instance.
     * @since 2.0.0
     */
    ElementaryFile& setHeader(const std::shared_ptr<FileHeaderAdapter> header);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    uint8_t getSfi() const override;

    /**
     * {@inheritDoc}
     *
     * C++: return type is actually a FileHeaderAdapter
     *
     * @since 2.0.0
     */
    const std::shared_ptr<FileHeader> getHeader() const override;

    /**
     * {@inheritDoc}
     *
     * C++: return type is actually a FileDataAdapter
     *
     * @since 2.0.0
     */
    const std::shared_ptr<FileData> getData() const override;

    /**
     * Comparison is based on field "sfi".
     *
     * @param o the object to compare.
     * @return the comparison evaluation
     * @since 2.0.0
     */
    bool operator==(const ElementaryFileAdapter& o) const;

    /**
     * Comparison is based on field "sfi".
     *
     * @param o the object to compare.
     * @return the comparison evaluation
     * @since 2.0.0
     */
    bool operator==(const std::shared_ptr<ElementaryFileAdapter> o) const;

    /**
     *
     */
    friend std::ostream& operator<<(std::ostream& os, const ElementaryFileAdapter& efa);

    /**
     *
     */
    friend std::ostream& operator<<(std::ostream& os,
                                    const std::shared_ptr<ElementaryFileAdapter> efa);

private:
    /**
     *
     */
    const uint8_t mSfi;

    /**
     *
     */
    std::shared_ptr<FileHeaderAdapter> mHeader;

    /**
     *
     */
    const std::shared_ptr<FileDataAdapter> mData;
};

}
}
}
