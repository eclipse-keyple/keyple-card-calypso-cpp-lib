#include "CmdSamWriteKey.h"

/* Keyple Card Calypso */
#include "CalypsoSamAccessForbiddenException.h"
#include "CalypsoSamCounterOverflowException.h"
#include "CalypsoSamDataAccessException.h"
#include "CalypsoSamIllegalParameterException.h"
#include "CalypsoSamIncorrectInputDataException.h"
#include "CalypsoSamSecurityDataException.h"
#include "SamUtilAdapter.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "IllegalArgumentException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp::exception;

const CalypsoSamCommand CmdSamWriteKey::mCommand = CalypsoSamCommand::WRITE_KEY;
const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamWriteKey::STATUS_TABLE = initStatusTable();


CmdSamWriteKey::CmdSamWriteKey(const CalypsoSam::ProductType productType, 
                               const uint8_t writingMode,
                               const uint8_t keyReference,
                               const std::vector<uint8_t>& keyData)
: AbstractSamCommand(mCommand, 0)
{
    const uint8_t cla = SamUtilAdapter::getClassByte(productType);

    if (keyData.empty()) {
        throw IllegalArgumentException("Key data null!");
    }

    if (keyData.size() < 48 && keyData.size() > 80) {
        throw IllegalArgumentException("Key data should be between 40 and 80 bytes long!");
    }

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, 
                            mCommand.getInstructionByte(), 
                            writingMode, 
                            keyReference, 
                            keyData)));
}

const std::map<const int, const std::shared_ptr<StatusProperties>>& CmdSamWriteKey::getStatusTable()
    const
{
    return STATUS_TABLE;
}

const std::map<const int, const std::shared_ptr<StatusProperties>> CmdSamWriteKey::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractSamCommand::STATUS_TABLE;

    m.insert({0x6700,
              std::make_shared<StatusProperties>("Incorrect Lc.",
                                                typeid(CalypsoSamIllegalParameterException))});
    m.insert({0x6900,
              std::make_shared<StatusProperties>("An event counter cannot be incremented.",
                                                typeid(CalypsoSamCounterOverflowException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Preconditions not satisfied.",
                                                 typeid(CalypsoSamAccessForbiddenException))});
    m.insert({0x6988,
              std::make_shared<StatusProperties>("Incorrect signature.",
                                                 typeid(CalypsoSamSecurityDataException))});
    m.insert({0x6A00,
              std::make_shared<StatusProperties>("P1 or P2 incorrect.",
                                                 typeid(CalypsoSamIllegalParameterException))});
    m.insert({0x6A80,
              std::make_shared<StatusProperties>("Incorrect plain or decrypted data.",
                                                 typeid(CalypsoSamIncorrectInputDataException))});
    m.insert({0x6A83,
              std::make_shared<StatusProperties>("Record not found: deciphering key not found.",
                                                 typeid(CalypsoSamDataAccessException))});
    m.insert({0x6A87,
              std::make_shared<StatusProperties>("Lc inconsistent with P1 or P2.",
                                                 typeid(CalypsoSamIncorrectInputDataException))});

    return m;
}

}
}
}
