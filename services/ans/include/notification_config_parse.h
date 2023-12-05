/*
* Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef NOTIFICATION_CONFIG_FILE_H
#define NOTIFICATION_CONFIG_FILE_H

#include <iostream>
#include <map>

namespace OHOS {
namespace Notification {
static enum ReminderModeFlag : unsigned int {
    kRMFRing = 0x01,       // Ring
    kRMFLockScreen = 0x02, // LockScreen
    kRMFHangUp = 0x04,     // HangUp
    kRMFLight = 0x08,      // Light
    kRMFVibration = 0x10,  // Vibration
} ReminderModeFlag;

class NotificationConfigFile {
public:
    NotificationConfigFile();
    NotificationConfigFile(const std::string &filePath);
    ~NotificationConfigFile();

private:
    static int binaryToDecimal(const char *binaryString);

public:
    static void getDefaultSlotFlagsMap(std::map<std::string, uint32_t> &slotFlagsMap);
    static bool getNotificationSlotFlagConfig(std::string &filePath,
        std::map<std::string, uint32_t> &slotFlagsMap);
    static bool parseNotificationConfigCcmFile(std::string &filePath,
        std::map<std::string, uint32_t> &slotFlagsMap);
};
} // namespace Notification
} // namespace OHOS

#endif
