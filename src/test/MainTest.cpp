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
#include <string>

#include "gtest/gtest.h"

#include "keyple/core/util/cpp/Logger.hpp"

using keyple::core::util::cpp::Logger;

int
main(int argc, char** argv)
{
    /* Initialize GTest */
    ::testing::InitGoogleTest(&argc, argv);

    Logger::setLoggerLevel(Logger::Level::logTrace);

    /* Run */
    return RUN_ALL_TESTS();
}
