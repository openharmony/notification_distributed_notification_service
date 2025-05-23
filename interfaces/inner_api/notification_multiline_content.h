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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_MULTILINE_CONTENT_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_MULTILINE_CONTENT_H

#include "notification_basic_content.h"
#include "want_agent.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {
class NotificationMultiLineContent : public NotificationBasicContent {
public:
    NotificationMultiLineContent() = default;

    ~NotificationMultiLineContent() = default;

    /**
     * @brief Sets the title to be displayed when this multi-line notification is expanded.
     * After this title is set, the title set by setTitle(string) will be displayed only
     * when this notification is in the collapsed state.
     *
     * @param exTitle Indicates the title to be displayed when this notification is expanded.
     */
    void SetExpandedTitle(const std::string &exTitle);

    /**
     * @brief Obtains the title that will be displayed for this multi-line notification when it is expanded.
     *
     * @return Returns the title to be displayed when this notification is expanded.
     */
    std::string GetExpandedTitle() const;

    /**
     * @brief Sets the brief text to be included in a multi-line notification.
     * The brief text is a summary of this multi-line notification and is displayed in the first line of
     * the notification. Similar to setAdditionalText(string), the font of the brief text is also
     * smaller than the notification text set by calling setText(string).
     * The positions where the brief text and additional text will display may conflict.
     * If both texts are set, only the additional text will be displayed.
     *
     * @param briefText Indicates the brief text to be included.
     */
    void SetBriefText(const std::string &briefText);

    /**
     * @brief Obtains the brief text that has been set by calling setBriefText(string) for this multi-line notification.
     *
     * @return Returns the brief text of this notification.
     */
    std::string GetBriefText() const;

    /**
     * @brief Adds a single line of text to this notification.
     * You can call this method up to seven times to add seven lines to a notification.
     *
     * @param oneLine Indicates the single line of text to be included.
     */
    void AddSingleLine(const std::string &oneLine);

    /**
     * @brief Obtains the list of lines included in this multi-line notification.
     *
     * @return Returns the list of lines included in this notification.
     */
    std::vector<std::string> GetAllLines() const;

    /**
     * @brief Sets the wantAgents for lines included in this multi-line notification.
     *
     * @param lineWantAgents which seted to line.
     */
    void SetLineWantAgents(std::vector<std::shared_ptr<AbilityRuntime::WantAgent::WantAgent>> lineWantAgents);

    /**
     * @brief Obtains the lineWantAgents included in the multi-line notification.
     *
     * @return lineWantAgents included in the multi-line notification.
     */
    std::vector<std::shared_ptr<AbilityRuntime::WantAgent::WantAgent>> GetLineWantAgents();

    /**
     * @brief Returns a string representation of the object.
     *
     * @return Returns a string representation of the object.
     */
    std::string Dump() override;

    /**
     * @brief Converts a NotificationMultiLineContent object into a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns true if succeed; returns false otherwise.
     */
    virtual bool ToJson(nlohmann::json &jsonObject) const override;

    /**
     * @brief Creates a NotificationMultiLineContent object from a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns the NotificationMultiLineContent object.
     */
    static NotificationMultiLineContent *FromJson(const nlohmann::json &jsonObject);

    /**
     * @brief Marshal a object into a Parcel.
     *
     * @param parcel the object into the parcel.
     * @return Returns true if succeed; returns false otherwise.
     */
    virtual bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Unmarshal object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns the NotificationMultiLineContent object.
     */
    static NotificationMultiLineContent *Unmarshalling(Parcel &parcel);

protected:
    /**
     * @brief Read a NotificationMultiLineContent object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ReadFromParcel(Parcel &parcel) override;

private:
    /**
     * the maximum size of vector is 7.
     */
    static const std::vector<std::string>::size_type MAX_LINES;

private:
    std::string expandedTitle_ {};
    std::string briefText_ {};
    std::vector<std::string> allLines_ {};
    std::vector<std::shared_ptr<AbilityRuntime::WantAgent::WantAgent>> lineWantAgents_ {};
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_MULTILINE_CONTENT_H