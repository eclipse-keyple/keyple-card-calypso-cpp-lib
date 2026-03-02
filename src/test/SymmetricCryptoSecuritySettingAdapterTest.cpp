/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the MIT License which is available at                             *
 * https://opensource.org/licenses/MIT.                                       *
 *                                                                            *
 * SPDX-License-Identifier: MIT                                               *
 ******************************************************************************/

#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "keyple/card/calypso/CalypsoExtensionService.hpp"
#include "keypop/calypso/card/transaction/SymmetricCryptoSecuritySetting.hpp"

#include "mock/SymmetricCryptoCardTransactionManagerFactoryMock.hpp"

using keyple::card::calypso::CalypsoExtensionService;
using keypop::calypso::card::transaction::SymmetricCryptoSecuritySetting;

using testing::Return;

class SymmetricCryptoSecuritySettingAdapterTest : public ::testing::Test {
protected:
    void
    SetUp() override
    {
        /* Mock crypto factory */
        symmetricCryptoCardTransactionManagerFactory = std::make_shared<
            SymmetricCryptoCardTransactionManagerFactoryMock>();
        EXPECT_CALL(
            *symmetricCryptoCardTransactionManagerFactory,
            getMaxCardApduLengthSupported())
            .WillRepeatedly(Return(250));
        EXPECT_CALL(
            *symmetricCryptoCardTransactionManagerFactory,
            isExtendedModeSupported())
            .WillRepeatedly(Return(true));

        /* Mock security setting */
        cardSecuritySetting
            = CalypsoExtensionService::getInstance()
                  ->getCalypsoCardApiFactory()
                  ->createSymmetricCryptoSecuritySetting(
                      symmetricCryptoCardTransactionManagerFactory);
    }

    std::shared_ptr<SymmetricCryptoCardTransactionManagerFactoryMock>
        symmetricCryptoCardTransactionManagerFactory;
    std::shared_ptr<SymmetricCryptoSecuritySetting> cardSecuritySetting;
};

TEST_F(
    SymmetricCryptoSecuritySettingAdapterTest,
    initCryptoContextForNextTransaction_shouldRequestCryptoModule)
{
    EXPECT_CALL(
        *symmetricCryptoCardTransactionManagerFactory,
        preInitTerminalSessionContext())
        .WillOnce(Return());

    cardSecuritySetting->initCryptoContextForNextTransaction();
}
