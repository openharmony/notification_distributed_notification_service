/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

export enum NotificationFlagStatus {

    TYPE_NONE = 0,

    TYPE_OPEN = 1,

    TYPE_CLOSE = 2
}

export interface NotificationFlags {

    readonly soundEnabled?: NotificationFlagStatus;

    readonly vibrationEnabled?: NotificationFlagStatus;

    readonly reminderFlags?: number;
}

class NotificationFlagsInner implements NotificationFlags {

    public soundEnabled?: NotificationFlagStatus | undefined;

    public vibrationEnabled?: NotificationFlagStatus | undefined;

    public reminderFlags?: number | undefined;
}