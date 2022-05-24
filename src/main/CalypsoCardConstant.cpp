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

#include "CalypsoCardConstant.h"

namespace keyple {
namespace card {
namespace calypso {

const int CalypsoCardConstant::MASK_15_BITS = 0x7FFF;  /* 32 767 */
const int CalypsoCardConstant::MASK_3_BYTES = 0xFFFFFF; /* 16 777 215 */

/* SFI */
const int CalypsoCardConstant::SFI_MIN = 0;
const int CalypsoCardConstant::SFI_MAX = 30; /* 1Eh */

/* Record number */
const int CalypsoCardConstant::NB_REC_MIN = 1;
const int CalypsoCardConstant::NB_REC_MAX = 250;

/* Counter number */
const int CalypsoCardConstant::NB_CNT_MIN = 1;
const int CalypsoCardConstant::NB_CNT_MAX = 83; /* Equal to "250 / 3" */

/* Counter value */
const int CalypsoCardConstant::CNT_VALUE_MIN = 0;
const int CalypsoCardConstant::CNT_VALUE_MAX = MASK_3_BYTES;

/* Offset */
const int CalypsoCardConstant::OFFSET_MIN = 0;
const int CalypsoCardConstant::OFFSET_MAX = 249;
const int CalypsoCardConstant::OFFSET_BINARY_MAX = MASK_15_BITS;

/* Data */
const int CalypsoCardConstant::DATA_LENGTH_MIN = 1;
const int CalypsoCardConstant::DATA_LENGTH_MAX = 250;

/* File Type Values */
const int CalypsoCardConstant::FILE_TYPE_MF = 1;
const int CalypsoCardConstant::FILE_TYPE_DF = 2;
const int CalypsoCardConstant::FILE_TYPE_EF = 4;

/* EF Type Values */
const int CalypsoCardConstant::EF_TYPE_DF = 0;
const int CalypsoCardConstant::EF_TYPE_BINARY = 1;
const int CalypsoCardConstant::EF_TYPE_LINEAR = 2;
const int CalypsoCardConstant::EF_TYPE_CYCLIC = 4;
const int CalypsoCardConstant::EF_TYPE_SIMULATED_COUNTERS = 8;
const int CalypsoCardConstant::EF_TYPE_COUNTERS = 9;

/* Field offsets in select file response (tag/length excluded) */
const int CalypsoCardConstant::SEL_SFI_OFFSET = 0;
const int CalypsoCardConstant::SEL_TYPE_OFFSET = 1;
const int CalypsoCardConstant::SEL_EF_TYPE_OFFSET = 2;
const int CalypsoCardConstant::SEL_REC_SIZE_OFFSET = 3;
const int CalypsoCardConstant::SEL_NUM_REC_OFFSET = 4;
const int CalypsoCardConstant::SEL_AC_OFFSET = 5;
const int CalypsoCardConstant::SEL_AC_LENGTH = 4;
const int CalypsoCardConstant::SEL_NKEY_OFFSET = 9;
const int CalypsoCardConstant::SEL_NKEY_LENGTH = 4;
const int CalypsoCardConstant::SEL_DF_STATUS_OFFSET = 13;
const int CalypsoCardConstant::SEL_KVCS_OFFSET = 14;
const int CalypsoCardConstant::SEL_KIFS_OFFSET = 17;
const int CalypsoCardConstant::SEL_DATA_REF_OFFSET = 14;
const int CalypsoCardConstant::SEL_LID_OFFSET = 21;

/* PIN Code */
const int CalypsoCardConstant::PIN_LENGTH = 4;

/* Stored Value */
const uint8_t CalypsoCardConstant::STORED_VALUE_FILE_STRUCTURE_ID = 0x20;
const uint8_t CalypsoCardConstant::SV_RELOAD_LOG_FILE_SFI = 0x14;
const int CalypsoCardConstant::SV_RELOAD_LOG_FILE_NB_REC = 1;
const uint8_t CalypsoCardConstant::SV_DEBIT_LOG_FILE_SFI = 0x15;
const int CalypsoCardConstant::SV_DEBIT_LOG_FILE_NB_REC = 3;
const int CalypsoCardConstant::SV_LOG_FILE_REC_LENGTH = 29;

/* Payload capacity */
const int CalypsoCardConstant::PAYLOAD_CAPACITY_PRIME_REV3 = 250;

CalypsoCardConstant::CalypsoCardConstant() {}

}
}
}
