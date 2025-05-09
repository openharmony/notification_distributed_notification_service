/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_CONTENT_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_CONTENT_H

#include "notification_basic_content.h"
#include "notification_conversational_content.h"
#include "notification_json_convert.h"
#include "notification_long_text_content.h"
#include "notification_media_content.h"
#include "notification_multiline_content.h"
#include "notification_normal_content.h"
#include "notification_picture_content.h"
#include "notification_live_view_content.h"
#include "notification_local_live_view_content.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {
class NotificationContent : public Parcelable, public NotificationJsonConvertionBase {
public:
    enum class Type {
        /**
         * invalid type
         */
        NONE,
        /**
         * Indicates basic notifications. Such notifications are created using NotificationNormalContent.
         */
        BASIC_TEXT,
        /**
         * Indicates notifications that include a conversation among multiple users.
         * Such notifications are created using NotificationConversationalContent.
         */
        CONVERSATION,
        /**
         * Indicates notifications that include long text.
         * Such notifications are created using NotificationLongTextContent.
         */
        LONG_TEXT,
        /**
         * Indicates notifications that include media playback sessions.
         * Such notifications are created using NotificationMediaContent.
         */
        MEDIA,
        /**
         * Indicates notifications that include multiple independent lines of text.
         * Such notifications are created using NotificationMultiLineContent.
         */
        MULTILINE,
        /**
         * Indicates notifications that include a picture.
         * Such notifications are created using NotificationPictureContent.
         */
        PICTURE,
        /**
         * Indicates notifications that include local live view.
         * Such notifications are created using NotificationLocalLiveViewContent.
         */
        LOCAL_LIVE_VIEW,
		/**
         * Indicates notifications that include a live view.
         * Such notifications are created using NotificationLiveViewContent.
         */
        LIVE_VIEW,
        /**
         * invalid type
         * It is used as the upper limit of the enumerated value.
         */
        ILLEGAL_TYPE
    };

    /**
     * @brief A constructor used to create a NotificationNormalContent instance (obtained by calling
     * GetNotificationContent()) and set the content type to NotificationContent::Type::BASIC_TEXT (obtained by calling
     * GetContentType()).
     *
     * @param normalContent Indicates the NotificationNormalContent object.
     */
    explicit NotificationContent(const std::shared_ptr<NotificationNormalContent> &normalContent);

    /**
     * @brief A constructor used to create a NotificationLongTextContent instance (obtained by calling
     * GetNotificationContent()) and set the content type to NotificationContent::Type::LONG_TEXT (obtained by calling
     * GetContentType()).
     *
     * @param longTextContent Indicates the NotificationLongTextContent object.
     */
    explicit NotificationContent(const std::shared_ptr<NotificationLongTextContent> &longTextContent);

    /**
     * @brief A constructor used to create a NotificationPictureContent instance (obtained by calling
     * GetNotificationContent()) and set the content type to NotificationContent::Type::PICTURE (obtained by calling
     * GetContentType()).
     *
     * @param pictureContent Indicates the NotificationPictureContent object.
     */
    explicit NotificationContent(const std::shared_ptr<NotificationPictureContent> &pictureContent);

    /**
     * @brief A constructor used to create a NotificationConversationalContent instance (obtained by calling
     * GetNotificationContent()) and set the content type to NotificationContent::Type::CONVERSATION (obtained by
     * calling GetContentType()).
     *
     * @param conversationContent Indicates the NotificationConversationalContent object.
     */
    explicit NotificationContent(const std::shared_ptr<NotificationConversationalContent> &conversationContent);

    /**
     * @brief A constructor used to create a NotificationMultiLineContent instance (obtained by calling
     * GetNotificationContent()) and set the content type to NotificationContent::Type::MULTILINE (obtained by calling
     * GetContentType()).
     *
     * @param multiLineContent Indicates the NotificationMultiLineContent object.
     */
    explicit NotificationContent(const std::shared_ptr<NotificationMultiLineContent> &multiLineContent);

    /**
     * @brief A constructor used to create a NotificationMediaContent instance (obtained by calling
     * GetNotificationContent()) and set the content type to NotificationContent::Type::MEDIA (obtained by calling
     * GetContentType()).
     *
     * @param mediaContent Indicates the NotificationMediaContent object.
     */
    explicit NotificationContent(const std::shared_ptr<NotificationMediaContent> &mediaContent);

    /**
     * @brief A constructor used to create a NotificationLocalLiveViewContent instance (obtained by calling
     * GetNotificationContent()) and set the content type to NotificationContent::Type::LOCAL_LIVE_VIEW
     * (obtained by calling GetContentType()).
     *
     * @param localLiveViewContent Indicates the NotificationLocalLiveViewContent object.
     */
    explicit NotificationContent(const std::shared_ptr<NotificationLocalLiveViewContent> &localLiveViewContent);

    /**
     * @brief A constructor used to create a NotificationLiveViewContent instance (obtained by calling
     * GetNotificationContent()) and set the content type to NotificationContent::Type::LIVE_VIEW (obtained by calling
     * GetContentType()).
     *
     * @param liveViewContent Indicates the NotificationMediaContent object.
     */
    explicit NotificationContent(const std::shared_ptr<NotificationLiveViewContent> &liveViewContent);
    virtual ~NotificationContent();

    /**
     * @brief Obtains the type value of the notification content.
     *
     * @return Returns the type value of the current content, which can be
     * NotificationContent::Type::BASIC_TEXT,
     * NotificationContent::Type::LONG_TEXT,
     * NotificationContent::Type::PICTURE,
     * NotificationContent::Type::CONVERSATION,
     * NotificationContent::Type::MULTILINE,
     * NotificationContent::Type::MEDIA,
     * NotificationContent::Type::LIVE_VIEW, or
     * NotificationContent::Type::LOCAL_LIVE_VIEW
     */
    NotificationContent::Type GetContentType() const;

    /**
     * @brief Obtains the object matching the current notification content.
     *
     * @return Returns the content object, which can be NotificationLongTextContent,
     * NotificationNormalContent,
     * NotificationPictureContent,
     * NotificationConversationalContent,
     * NotificationMultiLineContent, or
     * NotificationMediaContent.
     */
    std::shared_ptr<NotificationBasicContent> GetNotificationContent() const;

    /**
     * @brief Returns a string representation of the object.
     *
     * @return Returns a string representation of the object.
     */
    std::string Dump();

    /**
     * @brief Converts a NotificationContent object into a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ToJson(nlohmann::json &jsonObject) const override;

    /**
     * @brief Creates a NotificationContent object from a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns the NotificationContent.
     */
    static NotificationContent *FromJson(const nlohmann::json &jsonObject);

    /**
     * @brief Marshal a object into a Parcel.
     *
     * @param parcel Indicates the object into the parcel.
     * @return Returns true if succeed; returns false otherwise.
     */
    virtual bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Unmarshal object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns the NotificationContent.
     */
    static NotificationContent *Unmarshalling(Parcel &parcel);

    /**
     * @brief convert string contentType to NotificationContent contentType.
     *
     * @param strContentType string contentType
     * @param contentType NotificationContent contentType
     * @return Returns the result for converting string contentType to NotificationContent contentType.
     */
    static bool GetContentTypeByString(const std::string &strContentType, NotificationContent::Type &contentType);

    inline void ResetToBasicContent() const
    {
        contentType_ = NotificationContent::Type::BASIC_TEXT;
        content_->SetContentType(static_cast<int32_t>(NotificationContent::Type::BASIC_TEXT));
    }

private:
    NotificationContent() = default;

    /**
     * @brief Read data from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns true if read success; returns false otherwise.
     */
    bool ReadFromParcel(Parcel &parcel);

    /**
     * @brief Convert JSON object to NotificationContent object.
     *
     * @param target Indicates the NotificationContent object.
     * @param jsonObject Indicates the JSON object.
     * @return Returns true if the conversion is successful; returns false otherwise.
     */
    static bool ConvertJsonToContent(NotificationContent *target, const nlohmann::json &jsonObject);

public:
    constexpr static const char* CONTENT_TYPE_NONE = "None";
    constexpr static const char* CONTENT_TYPE_BASIC_TEXT = "Basic_text";
    constexpr static const char* CONTENT_TYPE_CONVERSATION = "Conversation";
    constexpr static const char* CONTENT_TYPE_LONG_TEXT = "Long_text";
    constexpr static const char* CONTENT_TYPE_MEDIA = "Media";
    constexpr static const char* CONTENT_TYPE_MULTILINE = "Mutiline";
    constexpr static const char* CONTENT_TYPE_PICTURE = "Picture";
    constexpr static const char* CONTENT_TYPE_LOCAL_LIVE_VIEW = "Local_live_view";
    constexpr static const char* CONTENT_TYPE_LIVE_VIEW = "Live_view";

private:
    mutable NotificationContent::Type contentType_ {NotificationContent::Type::NONE};
    std::shared_ptr<NotificationBasicContent> content_ {};
    static std::map<std::string, NotificationContent::Type> convertStrToContentType_;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_CONTENT_H
