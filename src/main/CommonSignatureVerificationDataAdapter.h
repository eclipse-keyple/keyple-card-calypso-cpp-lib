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

#include <memory>

/* Calypsonet Terminal Calypso */
#include "CommonSignatureVerificationData.h"

/* Keyple Core Util */
#include "IllegalStateException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::transaction;
using namespace keyple::core::util::cpp::exception;

/**
 * (package-private)<br>
 * Implementation of CommonSignatureVerificationData.
 *
 * @param <T> The type of the lowest level child object.
 * @since 2.2.0
 */
template <typename T>
class CommonSignatureVerificationDataAdapter : virtual public CommonSignatureVerificationData<T> {
public:
    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    T& setData(const std::vector<uint8_t>& data,
               const std::vector<uint8_t>& signature,
               const uint8_t kif,
               const uint8_t kvc) override
    {
        mData = data;
        mSignature = signature;
        mKif = kif;
        mKvc = kvc;

        return *mCurrentInstance;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    T& setKeyDiversifier(const std::vector<uint8_t>& diversifier) override
    {
        mKeyDiversifier = diversifier;

        return *mCurrentInstance;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    bool isSignatureValid() const override
    {
        if (mIsSignatureValid == nullptr) {
            throw IllegalStateException("The command has not yet been processed");
        }

        return *mIsSignatureValid;
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
     * @return A not empty array of the signature to check. It is required to check input data
     *         first.
     * @since 2.2.0
     */
    virtual const std::vector<uint8_t>& getSignature() const
    {
        return mSignature;
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
     * Sets the signature verification status.
     *
     * @param isSignatureValid True if the signature is valid.
     * @since 2.2.0
     */
    virtual void setSignatureValid(const bool isSignatureValid)
    {
        mIsSignatureValid = std::make_shared<bool>(isSignatureValid);
    }

private:
    /**
     *
     */
    T* mCurrentInstance = dynamic_cast<T*>(this);

    /**
     *
     */
    std::vector<uint8_t> mData;

    /**
     *
     */
    std::vector<uint8_t> mSignature;

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
    std::vector<uint8_t> mKeyDiversifier;

    /**
     *
     */
    std::shared_ptr<bool> mIsSignatureValid = nullptr;

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
