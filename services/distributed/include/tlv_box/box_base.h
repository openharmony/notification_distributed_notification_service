/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_BOX_BASE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_BOX_BASE_H

#include "tlv_box.h"
#include <memory>

namespace OHOS {
namespace Notification {
class BoxBase {
public:
    BoxBase();
    BoxBase(std::shared_ptr<TlvBox> box);
    void SetBox(std::shared_ptr<TlvBox> box);
    bool Serialize();

    unsigned char* GetByteBuffer();
    uint32_t GetByteLength();
    std::shared_ptr<TlvBox> box_;
};
}
}
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_BOX_BASE_H
