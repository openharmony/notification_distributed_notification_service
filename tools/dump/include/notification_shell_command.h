/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_TOOLS_DUMP_INCLUDE_NOTIFICATION_SHELL_COMMAND_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_TOOLS_DUMP_INCLUDE_NOTIFICATION_SHELL_COMMAND_H

#include "shell_command.h"
#include "ans_notification.h"

namespace OHOS {
namespace Notification {
class NotificationShellCommand : public OHOS::Notification::ShellCommand {
public:
    /**
     * @brief The constructor.
     *
     * @param argc Indicates the count of arguments.
     * @param argv Indicates the arguments.
     */
    NotificationShellCommand(int argc, char *argv[]);

    /**
     * @brief The deconstructor.
     */
    ~NotificationShellCommand() override {};

private:
    ErrCode CreateCommandMap() override;
    ErrCode Init() override;
    ErrCode RunAsHelpCommand();
    ErrCode RunAsDumpCommand();
    ErrCode RunAsSettingCommand();

    ErrCode RunHelp();
    void CheckDumpOpt();
    void SetDumpCmdInfo(std::string &cmd, std::string &bundle, int32_t &userId, ErrCode &ret, int32_t &recvUserId);
    ErrCode RunDumpCmd(const std::string& cmd, const std::string& bundle, int32_t userId, int32_t recvUserId,
        std::vector<std::string> &infos);
    ErrCode RunSetEnableCmd();
    ErrCode RunSetDeviceStatusCmd();
    void SetNativeToken();
    ErrCode RunSetSmartReminderEnabledCmd();
    ErrCode RunSetDistributedEnabledByBundleCmd();
    ErrCode RunSetDistributedEnabledBySlotCmd();
    ErrCode RunGetDeviceStatusCmd();

private:
    std::shared_ptr<AnsNotification> ans_;
};
}  // namespace Notification
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_TOOLS_DUMP_INCLUDE_NOTIFICATION_SHELL_COMMAND_H
