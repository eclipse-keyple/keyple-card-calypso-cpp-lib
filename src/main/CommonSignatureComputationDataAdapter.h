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

/* Calypsonet Terminal Calypso */
#include "CommonSignatureComputationData.h"

/* Keyple Core Util */
#include "IllegalStateException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::transaction;
using namespace keyple::core::util::cpp::exception;

/**
 * (package-private)<br>
 * Implementation of {@link CommonSignatureComputationData}.
 *
 * @param <T> The type of the lowest level child object.
 * @since 2.2.0
 */
template <typename T>
class CommonSignatureComputationDataAdapter : virtual public CommonSignatureComputationData<T> {
public:
    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    T& setData(const std::vector<uint8_t>& data, const uint8_t kif, const uint8_t kvc) override
    {
        mData = data;
        mKif = kif;
        mKvc = kvc;

        return dynamic_cast<T&>(*this);
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    T& setSignatureSize(const int size) override
    {
        mSignatureSize = size;

        return dynamic_cast<T&>(*this);
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    T& setKeyDiversifier(const std::vector<uint8_t>& diversifier) override
    {
        mKeyDiversifier = diversifier;

        return dynamic_cast<T&>(*this);
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    const std::vector<uint8_t>& getSignature() const override
    {
        if (!mSignatureProcessed) {
            throw IllegalStateException("The command has not yet been processed");
        }

        return mSignature;
    }

    /**
     * (package-private)<br>
     *
     * @return A not empty array of data. It is required to check input data first.
     * @since 2.2.0
     */
    virtual const std::vector<uint8_t>& getData() const
    {
        return mData;
    }


    /**
     * (package-private)<br>
     *
     * @return The KIF. It is required to check input data first.
     * @since 2.2.0
     */
    virtual uint8_t getKif() const
    {
        return mKif;
    }

    /**
     * (package-private)<br>
     *
     * @return The KVC. It is required to check input data first.
     * @since 2.2.0
     */
    virtual uint8_t getKvc() const
    {
        return mKvc;
    }

    /**
     * (package-private)<br>
     *
     * @return The signature size.
     * @since 2.2.0
     */
    virtual int getSignatureSize() const
    {
        return mSignatureSize;
    }

    /**
     * (package-private)<br>
     * Sets the computed signature.
     *
     * @param signature The computed signature.
     * @since 2.2.0
     */
    virtual void setSignature(const std::vector<uint8_t>& signature)
    {
        mSignature = signature;
    }

private:
    /**
     *
     */
    std::vector<uint8_t> mData;

    /**
     *
     */
    uint8_t mKif;

    /**
     *
     */
    uint8_t mKvc;

    /**
     *
     */
    int mSignatureSize = 8;

    /**
     *
     */
    std::vector<uint8_t> mKeyDiversifier;

    /**
     *
     */
    std::vector<uint8_t> mSignature;

    /**
     * C++: required to avoid pointer on mSignature
     */
    bool mSignatureProcessed = false;

    /**
     * (package-private)<br>
     *
     * @return Null if the key diversifier is not set.
     * @since 2.2.0
     */
    virtual const std::vector<uint8_t>& getKeyDiversifier() const
    {
        return mKeyDiversifier;
    }
};

}
}
}
