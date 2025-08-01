/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_SLOT_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_SLOT_H

#include "notification_content.h"
#include "notification_request.h"
#include "parcel.h"
#include "uri.h"

namespace OHOS {
namespace Notification {
static const uint32_t INVALID_REMINDER_MODE = 0xffffffff;
class NotificationSlot : public Parcelable {
public:
    enum NotificationLevel {
        LEVEL_NONE,       // the notification function is disabled.
        LEVEL_MIN,        // the notifications function is disabled on the notification panel,
                          // with no banner or prompt tone
        LEVEL_LOW,        // the notifications are displayed on the notification panel,
                          // with no banner or prompt tone
        LEVEL_DEFAULT,    // the notification function is enabled and notifications are displayed,
                          // on the notification panel, with a banner and a prompt tone.
        LEVEL_HIGH,       // the notifications are displayed on the notification panel,
                          // with a banner and a prompt tone
        LEVEL_UNDEFINED,  // the notification does not define an level.
    };

    enum AuthorizedStatus {
        AUTHORIZED,         // the slot has been authorized
        NOT_AUTHORIZED,     // the slot has not been authorized
    };

    /**
     * @brief A constructor used to initialize the type of a NotificationSlot object.
     *
     * @param type  Specifies the type of the NotificationSlot object,
     */
    NotificationSlot(NotificationConstant::SlotType type = NotificationConstant::SlotType::CUSTOM);

    ~NotificationSlot();

    /**
     * @brief Obtains whether the notification light is enabled in a NotificationSlot object,
     * which is set by SetEnableLight(bool).
     *
     * @return Returns true if the notification light is enabled; returns false otherwise.
     */
    bool CanEnableLight() const;

    /**
     * @brief Specifies whether to enable the notification light when a notification is received on the device,
     * provided that this device has a notification light.
     * @note SetEnableLight must be set before the NotificationHelper:AddNotificationSlot(NotificationSlot) method is
     * called. Otherwise, the settings will not take effect.
     *
     * @param isLightEnabled Specifies whether to enable the pulse notification light.
     *                       The value true indicates to enable the notification light,
     *                       and the value false indicates not to enable it.
     */
    void SetEnableLight(bool isLightEnabled);

    /**
     * @brief Obtains the vibration status of a NotificationSlot object,
     * which is set by SetEnableVibration(bool).
     *
     * @return Returns true if vibration is enabled; returns false otherwise.
     */
    bool CanVibrate() const;

    /**
     * @brief Sets whether to enable vibration when a notification is received.
     * @note SetEnableVibration(bool) must be set before the NotificationHelper::AddNotificationSlot(NotificationSlot)
     * method is called. Otherwise, the settings will not take effect.
     *
     * @param vibration Indicates whether to enable vibration when a notification is received.
     *                  If the value is true, vibration is enabled; if the value is false, vibration is disabled.
     */
    void SetEnableVibration(bool vibration);

    /**
     * @brief Obtains the description of a NotificationSlot object, which is set by SetDescription(string).
     *
     * @return Returns the description of the NotificationSlot object.
     */
    std::string GetDescription() const;

    /**
     * @brief Sets the description for a NotificationSlot object.
     * @note The setting of setDescription is effective regardless of whether a NotificationSlot object has been created
     * by NotificationHelper::AddNotificationSlot(NotificationSlot).
     *
     * @param description describes the NotificationSlot object.
     *                    The description is visible to users and its length must not exceed 1000 characters
     *                    (the excessive part is automatically truncated).
     */
    void SetDescription(const std::string &description);

    /**
     * @brief Obtains the ID of a NotificationSlot object.
     *
     * @return Returns the ID of the NotificationSlot object,
     *         which is set by NotificationSlot(string, string, NotificationLevel).
     */
    std::string GetId() const;

    /**
     * @brief Obtains the color of the notification light in a NotificationSlot object,
     * which is set by SetLedLightColor(int32_t).
     *
     * @return Returns the color of the notification light.
     */
    int32_t GetLedLightColor() const;

    /**
     * @brief Sets the color of the notification light to flash when a notification is received on the device,
     * provided that this device has a notification light and setEnableLight is called with the value true.
     * @note SetLedLightColor must be set before the NotificationHelper::AddNotificationSlot(NotificationSlot) method is
     * called. Otherwise, the settings will not take effect.
     *
     * @param color Indicates the color of the notification light.
     */
    void SetLedLightColor(int32_t color);

    /**
     * @brief Obtains the level of a NotificationSlot object, which is set by SetLevel(NotificationLevel).
     *
     * @return Returns the level of the NotificationSlot object.
     */
    NotificationLevel GetLevel() const;

    /**
     * @brief Sets the level of a NotificationSlot object.
     * @note SetLevel must be set before the NotificationHelper::AddNotificationSlot(NotificationSlot) method is called.
     *       Otherwise, the settings will not take effect.
     *
     * @param level Specifies the level of the NotificationSlot object, which determines the notification display
     * effect. The value can be LEVEL_NONE, LEVEL_MIN, LEVEL_LOW, LEVEL_DEFAULT, or LEVEL_HIGH.
     */
    void SetLevel(NotificationLevel level);

    /**
     * @brief Sets the slotflags of a NotificationSlot object.
     * @note SetSlotFlags must be set before the NotificationHelper::AddNotificationSlot(NotificationSlot)
     * method is called.
     *       Otherwise, the settings will not take effect.
     *
     * @param slotFlags Specifies the slotflags of the NotificationSlot object,
     * @note which determines the notification display effect.
     * The value can be LEVEL_NONE, LEVEL_MIN, LEVEL_LOW, LEVEL_DEFAULT, or LEVEL_HIGH.
     */
    void SetSlotFlags(uint32_t slotFlags);

    /**
     * @brief Obtains the slotflags of a NotificationSlot object, which is set by SetSlotFlags(uint32_t slotFlags).
     *
     * @return Returns the slotflags of the NotificationSlot object.
     */
    uint32_t GetSlotFlags() const;

    /**
     * @brief Obtains the type of a NotificationSlot object, which is set by SetType(SlotType).
     *
     * @return Returns the Type of the NotificationSlot object.
     */
    NotificationConstant::SlotType GetType() const;

    /**
     * @brief Sets the type of a NotificationSlot object.
     * @note Settype must be set before the NotificationHelper::AddNotificationSlot(NotificationSlot) method is called.
     *       Otherwise, the settings will not take effect.
     *
     * @param type Specifies the type of the NotificationSlot object, which determines the notification remind mode.
     *        The value can be DEFAULT, SOCIAL_COMMUNICATION, SERVICE_REMINDER, CONTENT_INFORMATION, or OTHER.
     */
    void SetType(NotificationConstant::SlotType type);

    /**
     * @brief Obtains the notification display effect of a NotificationSlot object on the lock screen,
     * which is set by SetLockscreenVisibleness(int32_t).
     * @note This method specifies different effects for displaying notifications on the lock screen in order to protect
     * user privacy. The setting takes effect only when the lock screen notifications function is enabled for an
     * application in system notification settings.
     *
     * @return Returns the notification display effect of the NotificationSlot object on the lock screen.
     */
    NotificationConstant::VisiblenessType GetLockScreenVisibleness() const;

    /**
     * @brief Sets whether and how to display notifications on the lock screen.
     *
     * @param visibleness Specifies the notification display effect on the lock screen, which can be set to
     *                    NO_OVERRIDE, PUBLIC, PRIVATE, or SECRET.
     */
    void SetLockscreenVisibleness(NotificationConstant::VisiblenessType visibleness);

    /**
     * @brief Obtains the name of a NotificationSlot object.
     *
     * @return Returns the name of the NotificationSlot object, which is set by SetName(string).
     */
    std::string GetName() const;

    /**
     * @brief Obtains the prompt tone of a NotificationSlot object, which is set by SetSound(Uri).
     *
     * @return Returns the prompt tone of the NotificationSlot object.
     */
    Uri GetSound() const;

    /**
     * @brief Sets a prompt tone for a NotificationSlot object, which will be played after a notification is received.
     * @note SetSound must be set before the NotificationHelper:AddNotificationSlot(NotificationSlot) method is called.
     *       Otherwise, the settings will not take effect.
     *
     * @param sound Specifies the path for the prompt tone.
     */
    void SetSound(const Uri &sound);

    /**
     * @brief Obtains the vibration style of notifications in this NotificationSlot.
     *
     * @return Returns the vibration style of this NotificationSlot.
     */
    std::vector<int64_t> GetVibrationStyle() const;

    /**
     * @brief Sets the vibration style for notifications in this NotificationSlot.
     * @note If an empty array or null is passed to this method, the system then calls
     *       SetEnableVibration(bool) with the input parameter set to false.
     *       If a valid value is passed to this method, the system calls SetEnableVibration(bool) with the input
     *       parameter set to true. This method takes effect only before
     *       NotificationHelper::AddNotificationSlot(NotificationSlot) is called.
     *
     * @param vibration Indicates the vibration style to set.
     */
    void SetVibrationStyle(const std::vector<int64_t> &vibration);

    /**
     * @brief Obtains whether DND mode is bypassed for a NotificationSlot object,
     * which is set by EnableBypassDnd(bool).
     *
     * @return Returns true if DND mode is bypassed; returns false otherwise.
     */
    bool IsEnableBypassDnd() const;

    /**
     * @brief Sets whether to bypass Do not disturb (DND) mode in the system.
     * @note The setting of EnableBypassDnd takes effect only when the Allow interruptions function
     *       is enabled for an application in system notification settings.
     *
     * @param isBypassDnd Specifies whether to bypass DND mode for an application.
     *                    If the value is true, DND mode is bypassed;
     *                    if the value is false, DND mode is not bypassed.
     */
    void EnableBypassDnd(bool isBypassDnd);

    /**
     * @brief Obtains the application icon badge status of a NotificationSlot object,
     * which is set by EnableBadge(bool).
     *
     * @return Returns true if the application icon badge is enabled; returns false otherwise.
     */
    bool IsShowBadge() const;

    /**
     * @brief Sets whether to display application icon badges (digits or dots in the corner of the application icon)
     * on the home screen after a notification is received.
     * @note EnableBadge must be set before the NotificationHelper:AddNotificationSlot(NotificationSlot) method is
     * called. Otherwise, the settings will not take effect.
     *
     * @param isShowBadge Specifies whether to display the application icon badge.
     *                    If the value is true, the application icon badge is enabled;
     *                    if the value is false, the application icon badge is disabled..
     */
    void EnableBadge(bool isShowBadge);

    /**
     * @brief Set whether the application slot enable.
     * @note If the slot enable status is false, the notification cannot be publish.
     *
     * @param enabled Specifies whether to enable slot.
     */
    void SetEnable(bool enabled);

    /**
     * @brief Obtains whether the application slot is enabled.
     *
     * @return Returns true if the slot enabled; returns false otherwise.
     */
    bool GetEnable() const;

    /**
     * @brief Set whether the application slot is force control.
     * @note If the slot is force control, the notification ability is not affected by the bundle.
     *
     * @param isForceControl Specifies whether is force control.
     */
    void SetForceControl(bool isForceControl);

    /**
     * @brief Obtains whether the application slot is force control.
     *
     * @return Returns true if the slot is force control; returns false otherwise.
     */
    bool GetForceControl() const;

    /**
     * @brief Sets the authorizedStatus of a NotificationSlot object.
     * @note SetSlotFlags must be set before the NotificationHelper::AddNotificationSlot(NotificationSlot)
     * method is called.
     *       Otherwise, the settings will not take effect.
     *
     * @param slotFlags Specifies the authorizedStatus of the NotificationSlot object,
     * @note which determines the notification authorized status.
     * The value can be 0,1.
     */
    void SetAuthorizedStatus(int32_t status);

    /**
     * @brief Obtains the authorizedStatus of a NotificationSlot object,
     *        which is set by SetAuthorizedStatus(int32_t status).
     *
     * @return Returns the authorizedStatus of the NotificationSlot object.
     */
    int32_t GetAuthorizedStatus() const;

    /**
     * @brief Add the authHintCnt of a NotificationSlot object.
     * @note which determines the notification authorized hint count.
     * The value can be 0,1.
     */
    void AddAuthHintCnt();

    /**
     * @brief Set the authHintCnt of a NotificationSlot object.
     * @param count Specifies the authHintCnt of the NotificationSlot object,
     * @note which determines the notification authorized hint count.
     * The value can be 0,1.
     */
    void SetAuthHintCnt(int32_t count);

    /**
     * @brief Set reminder mode of a NotificationSlot object.
     * @param reminderMode Specifies the reminder mode of the NotificationSlot object,
     * @note which determines the notification reminder mode.
     */
    void SetReminderMode(uint32_t reminderMode);

    /**
     * @brief Obtains the reminder mode of a NotificationSlot object
     * @return Returns the reminder mode of the NotificationSlot object.
     */
    uint32_t GetReminderMode() const;

    /**
     * @brief Obtains the authHintCnt of a NotificationSlot object, which is set by SetAuthHintCnt(int32_t count).
     *
     * @return Returns the authHintCnt of the NotificationSlot object.
     */
    int32_t GetAuthHintCnt() const;

    /**
     * @brief Dumps a string representation of the object.
     *
     * @return Returns a string representation of the object.
     */
    std::string Dump() const;

    /**
     * @brief Obtains the reminder mode of a NotificationSlot object
     * @return Returns the reminder mode of the NotificationSlot object with silentReminder.
     */
    uint32_t GetSilentReminderMode() const;

    /**
     * @brief Marshals a NotificationSlot object into a Parcel.
     *
     * @param parcel Indicates the Parcel object for marshalling.
     * @return Returns true if the marshalling is successful; returns false otherwise.
     */
    virtual bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Unmarshals a NotificationSlot object from a Parcel.
     *
     * @param parcel Indicates the Parcel object for unmarshalling.
     * @return Returns the NotificationSlot object.
     */
    static NotificationSlot *Unmarshalling(Parcel &parcel);

    /**
     * @brief convert string slottype to NotificationConstant slottype.
     *
     * @param strSlotType string slottype
     * @param slotType NotificationConstant slottype
     * @return Returns the result for converting string slottype to NotificationConstant slottype.
     */
    static bool GetSlotTypeByString(const std::string &strSlotType, NotificationConstant::SlotType &slotType);

private:
    /**
     * @brief Read NotificationSlot object from a Parcel.
     *
     * @param parcel Indicates the Parcel object for unmarshalling.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ReadFromParcel(Parcel &parcel);

    /**
     * @brief Merge the contents of vector and output a string
     *
     * @param mergeVector Indicates the vector which will be merged
     * @return Returns the string that has contents of the vector
     */
    std::string MergeVectorToString(const std::vector<int64_t> &mergeVector) const;

    /**
     * @brief If string length exceed 1000 characters, the excessive part is automatically truncated.
     *
     * @param in Indicates the sting which will be truncated
     * @return Returns the string that has been truncated.
     */
    std::string TruncateString(const std::string &in);

    /**
     * @brief Sets the name of a NotificationSlot object.
     * @note The setting of SetName is effective regardless of whether a NotificationSlot object has been created by
     *       NotificationHelper:AddNotificationSlot(NotificationSlot).
     *
     * @param name Specifies the name of the NotificationSlot object.
     *             The name is visible to users, and its length must not exceed 1000 characters
     *             (the excessive part is automatically truncated).
     */
    void SetName(const std::string &name);

    /**
     * @brief Obtains the default reminder mode of a NotificationSlot object
     * @return Returns the default reminder mode of slot.
     */
    uint32_t GetDefaultReminderMode() const;
public:
    constexpr static const char* SOCIAL_COMMUNICATION = "Social_communication";
    constexpr static const char* SERVICE_REMINDER = "Service_reminder";
    constexpr static const char* CONTENT_INFORMATION = "Content_information";
    constexpr static const char* LIVE_VIEW = "Live_view";
    constexpr static const char* CUSTOM_SERVICE = "Custom_service";
    constexpr static const char* OTHER = "Other";
    constexpr static const char* EMERGENCY_INFORMATION = "Emergency_information";
    constexpr static const char* SPLIT_FLAG = "|";

private:
    std::string id_ {};
    std::string name_ {};
    bool isLightEnabled_ {false};
    bool isVibrationEnabled_ {false};
    bool isShowBadge_ {true};
    bool isBypassDnd_ {false};
    std::string description_ {};
    int32_t lightColor_ {0};
    NotificationLevel level_ {LEVEL_DEFAULT};
    NotificationConstant::SlotType type_ {};
    NotificationConstant::VisiblenessType lockScreenVisibleness_ {NotificationConstant::VisiblenessType::NO_OVERRIDE};
    Uri sound_;
    std::vector<int64_t> vibrationValues_ {};
    bool enabled_ {true};
    uint32_t slotFlags_{0};
    bool isForceControl_ {false};
    int32_t authorizedStatus_ {AuthorizedStatus::NOT_AUTHORIZED};
    int32_t authHintCnt_ = {0};
    uint32_t reminderMode_ = {INVALID_REMINDER_MODE};

    // no object in parcel
    static constexpr int32_t VALUE_NULL = -1;
    // object exist in parcel
    static constexpr int32_t VALUE_OBJECT = 1;
    static std::map<std::string, NotificationConstant::SlotType> convertStrToSlotType_;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_SLOT_H
