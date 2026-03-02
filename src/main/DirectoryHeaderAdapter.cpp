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

#include "keyple/card/calypso/DirectoryHeaderAdapter.hpp"

#include <memory>
#include <string>
#include <vector>

#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::cpp::exception::IllegalStateException;

const std::string DirectoryHeaderAdapter::LEVEL_STR = "level";

DirectoryHeaderAdapter::DirectoryHeaderBuilder::DirectoryHeaderBuilder()
{
}

DirectoryHeaderAdapter::DirectoryHeaderBuilder&
DirectoryHeaderAdapter::DirectoryHeaderBuilder::lid(std::uint16_t lid)
{
    mLid = lid;

    return *this;
}

DirectoryHeaderAdapter::DirectoryHeaderBuilder&
DirectoryHeaderAdapter::DirectoryHeaderBuilder::accessConditions(
    const std::vector<std::uint8_t>& accessConditions)
{
    mAccessConditions = accessConditions;

    return *this;
}

DirectoryHeaderAdapter::DirectoryHeaderBuilder&
DirectoryHeaderAdapter::DirectoryHeaderBuilder::keyIndexes(
    const std::vector<std::uint8_t>& keyIndexes)
{
    mKeyIndexes = keyIndexes;

    return *this;
}

DirectoryHeaderAdapter::DirectoryHeaderBuilder&
DirectoryHeaderAdapter::DirectoryHeaderBuilder::dfStatus(std::uint8_t dfStatus)
{
    mDfStatus = dfStatus;

    return *this;
}

DirectoryHeaderAdapter::DirectoryHeaderBuilder&
DirectoryHeaderAdapter::DirectoryHeaderBuilder::kif(
    WriteAccessLevel level, std::uint8_t kif)
{
    mKif.insert({level, kif});

    return *this;
}

DirectoryHeaderAdapter::DirectoryHeaderBuilder&
DirectoryHeaderAdapter::DirectoryHeaderBuilder::kvc(
    WriteAccessLevel level, std::uint8_t kvc)
{
    mKvc.insert({level, kvc});

    return *this;
}

std::unique_ptr<DirectoryHeader>
DirectoryHeaderAdapter::DirectoryHeaderBuilder::build()
{
    return std::unique_ptr<DirectoryHeaderAdapter>(
        new DirectoryHeaderAdapter(this));
}

DirectoryHeaderAdapter::DirectoryHeaderAdapter(DirectoryHeaderBuilder* builder)
: mLid(builder->mLid)
, mAccessConditions(builder->mAccessConditions)
, mKeyIndexes(builder->mKeyIndexes)
, mDfStatus(builder->mDfStatus)
, mKif(builder->mKif)
, mKvc(builder->mKvc)
{
}

std::uint16_t
DirectoryHeaderAdapter::getLid() const
{
    return mLid;
}

const std::vector<std::uint8_t>&
DirectoryHeaderAdapter::getAccessConditions() const
{
    return mAccessConditions;
}

const std::vector<std::uint8_t>&
DirectoryHeaderAdapter::getKeyIndexes() const
{
    return mKeyIndexes;
}

std::uint8_t
DirectoryHeaderAdapter::getDfStatus() const
{
    return mDfStatus;
}

std::uint8_t
DirectoryHeaderAdapter::getKif(WriteAccessLevel writeAccessLevel) const
{
    const auto it = mKif.find(writeAccessLevel);
    if (it != mKif.end()) {
        return it->second;
    } else {
        throw IllegalStateException("writeAccessLevel should exist in map");
    }
}

std::uint8_t
DirectoryHeaderAdapter::getKvc(WriteAccessLevel writeAccessLevel) const
{
    const auto it = mKvc.find(writeAccessLevel);
    if (it != mKvc.end()) {
        return it->second;
    } else {
        throw IllegalStateException("writeAccessLevel should exist in map");
    }
}

std::unique_ptr<DirectoryHeaderAdapter::DirectoryHeaderBuilder>
DirectoryHeaderAdapter::builder()
{
    return std::unique_ptr<DirectoryHeaderAdapter::DirectoryHeaderBuilder>(
        new DirectoryHeaderAdapter::DirectoryHeaderBuilder());
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
