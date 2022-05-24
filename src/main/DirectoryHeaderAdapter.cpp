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

#include "DirectoryHeaderAdapter.h"

/* Keyple Core Util */
#include "IllegalStateException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util::cpp::exception;

using DirectoryHeaderBuilder = DirectoryHeaderAdapter::DirectoryHeaderBuilder;

const std::string DirectoryHeaderAdapter::LEVEL_STR = "level";

/* DIRECTORY HEADER BUILDER --------------------------------------------------------------------- */

DirectoryHeaderBuilder::DirectoryHeaderBuilder() {}

DirectoryHeaderBuilder& DirectoryHeaderBuilder::lid(const uint16_t lid)
{
    mLid = lid;

    return* this;
}

DirectoryHeaderBuilder& DirectoryHeaderBuilder::accessConditions(
    const std::vector<uint8_t>& accessConditions)
{
    mAccessConditions = accessConditions;

    return *this;
}

DirectoryHeaderBuilder& DirectoryHeaderBuilder::keyIndexes(
    const std::vector<uint8_t>& keyIndexes)
{
    mKeyIndexes = keyIndexes;

    return *this;
}

DirectoryHeaderBuilder& DirectoryHeaderBuilder::dfStatus(const uint8_t dfStatus)
{
    mDfStatus = dfStatus;

    return *this;
}

DirectoryHeaderBuilder& DirectoryHeaderBuilder::kif(const WriteAccessLevel level,
                                                    const uint8_t kif)
{
    mKif.insert({level, kif});

    return *this;
}

DirectoryHeaderBuilder& DirectoryHeaderBuilder::kvc(const WriteAccessLevel level, const uint8_t kvc)
{
    mKvc.insert({level, kvc});

    return *this;
}

const std::shared_ptr<DirectoryHeader> DirectoryHeaderBuilder::build()
{
    return std::shared_ptr<DirectoryHeaderAdapter>(new DirectoryHeaderAdapter(shared_from_this()));
}

/* DIRECTORY HEADER ADAPTER --------------------------------------------------------------------- */

DirectoryHeaderAdapter::DirectoryHeaderAdapter(
  const std::shared_ptr<DirectoryHeaderBuilder> builder)
: mLid(builder->mLid),
  mAccessConditions(builder->mAccessConditions),
  mKeyIndexes(builder->mKeyIndexes),
  mDfStatus(builder->mDfStatus),
  mKif(builder->mKif),
  mKvc(builder->mKvc) {}

uint16_t DirectoryHeaderAdapter::getLid() const
{
    return mLid;
}

const std::vector<uint8_t>& DirectoryHeaderAdapter::getAccessConditions() const
{
    return mAccessConditions;
}

const std::vector<uint8_t>& DirectoryHeaderAdapter::getKeyIndexes() const
{
    return mKeyIndexes;
}

uint8_t DirectoryHeaderAdapter::getDfStatus() const
{
    return mDfStatus;
}

uint8_t DirectoryHeaderAdapter::getKif(const WriteAccessLevel writeAccessLevel) const
{;
    const auto it = mKif.find(writeAccessLevel);
    if (it != mKif.end()) {
        return it->second;
    } else {
        throw IllegalStateException("writeAccessLevel should exist in map");
    }
}

uint8_t DirectoryHeaderAdapter::getKvc(const WriteAccessLevel writeAccessLevel) const
{
    const auto it = mKvc.find(writeAccessLevel);
    if (it != mKvc.end()) {
        return it->second;
    } else {
        throw IllegalStateException("writeAccessLevel should exist in map");
    }
}

std::shared_ptr<DirectoryHeaderBuilder> DirectoryHeaderAdapter::builder()
{
    return std::shared_ptr<DirectoryHeaderBuilder>(new DirectoryHeaderBuilder());
}

}
}
}
