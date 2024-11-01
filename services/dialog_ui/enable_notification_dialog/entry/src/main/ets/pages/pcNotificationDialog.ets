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

import bundleResourceManager from '@ohos.bundle.bundleResourceManager';
import display from '@ohos.display';
import window from '@ohos.window';
import { titleTrim } from '../common/utils';
import Constants from '../common/constant';
import fs from '@ohos.file.fs';
import configPolicy from '@ohos.configPolicy';
import { EnableNotificationDialog } from '../ServiceExtAbility/NotificationServiceExtAbility';
import { Callback} from '@ohos.base';
import UIExtensionContentSession from '@ohos.app.ability.UIExtensionContentSession';
import i18n from '@ohos.i18n';

const TAG = 'NotificationDialog_Service ';

const LAN_EN = 'These may include banners, sounds and more. You can change this in Settings.';
const LAN_CN = '通知提醒方式可能包括横幅、响铃等。可前往“设置” 更改。';
const LAN_HK = '通知提醒方式可能包括橫幅、響鬧等。可前往「設定」更改。';
const LAN_TW = '通知提醒方式可能包括橫幅、響鈴等。可前往「設定」變更。';
const LAN_BO = 'བརྡ་ཐོ་དྲན་སྐུལ་གྱི་ཐབས་ལམ་ལ་སྒོ་ལྕགས་བརྙན་ཡོལ་དང་། འཕྲེད་བྱང་། དྲིལ་སྒྲ། སྦིར་བརྡ་སོགས་ཚུད་སྲིད། ༼སྒྲིག་འགོད་༽ལ་བསྐྱོད་ནས་བཅོས་ཆོག';
const LAN_UG = 'قۇلۇپ ئېكرانى، بالداق، ئاۋاز ۋە تىترەش شۇلارنىڭ ئىچىدە. تەڭشەكتىن ئۆزگەرتەلەيسىز.';

const permission: Record<string, Resource> = {
  'label': $r('app.string.group_label_notification'),
  'icon': $r('app.media.ic_public_ring'),
  'reason': $r('app.string.reason'),
};

let storage = LocalStorage.getShared();

@Extend(Button) function customizeButton() {
  .type(ButtonType.Normal)
  .backgroundColor($r('sys.color.comp_background_tertiary'))
  .fontColor($r('sys.color.font_emphasize'))
  .fontSize($r('sys.float.Body_L'))
  .fontWeight(FontWeight.Medium)
  .height(Constants.PC_BUTTON_HEIGHT)
  .width('50%')
  .borderRadius(Constants.PC_RDIUS_8)
  .flexGrow(Constants.FLEX_GROW)
}

@Entry(storage)
@Component
struct NotificationDialogPage {
  @StorageLink('isUpdate') isUpdate: number = 0;

  privacyDialogController: CustomDialogController = new CustomDialogController({
    builder: PermissionDialog({ isUpdate: $isUpdate }),
    autoCancel: false,
    alignment: DialogAlignment.Center,
    customStyle: true,
    cornerRadius: Constants.PC_RDIUS_16,
    maskColor: $r('sys.color.ohos_id_color_mask_thin'),
    onWillDismiss: (dismissDialogAction: DismissDialogAction) => {
      console.info(TAG, `dialog onWillDismiss reason= : ${JSON.stringify(dismissDialogAction.reason)}`);
    }
  });

  build() {}

  aboutToAppear() {
    this.privacyDialogController.open();
  }

  onPageShow() {
  }
}

@CustomDialog
struct PermissionDialog {
  @State appName: string = '';
  @State content: string = LAN_CN;
  @State naviHeight: number = 0;
  @State isBottomPopover: boolean = false;
  @StorageLink('clicked') clicked: boolean = false;
  @Link @Watch('updateOnPageShow') isUpdate: number;
  dialog?: EnableNotificationDialog;
  session?: UIExtensionContentSession;
  controller?: CustomDialogController;

  build() {
    Row() {
      Flex({ justifyContent: FlexAlign.Center, alignItems: this.isBottomPopover ? ItemAlign.End : ItemAlign.Center }) {
        Column() {
          Scroll() {
            Column() {
              Row() {
                Image(permission.icon)
                .width(Constants.DIALOG_ICON_WIDTH)
                .height(Constants.DIALOG_ICON_HEIGHT)
                .margin({
                  top: Constants.PC_ICON_MARGIN_TOP
                })
                .draggable(false)
              }
              Row() {
                Flex({ justifyContent: FlexAlign.Center }) {
                  Text() {
                    Span(getContext(this).resourceManager.getStringSync(permission.label.id).replace('%s', this.appName))
                  }
                  .fontSize($r('sys.float.Title_S'))
                  .fontColor($r('sys.color.font_primary'))
                  .fontWeight(FontWeight.Bold)
                  .maxLines(2)
                  .textOverflow({overflow: TextOverflow.Ellipsis})
                  .margin({
                    left: Constants.PC_TITLE_MARGIN_SIDE,
                    right: Constants.PC_TITLE_MARGIN_SIDE,
                    top: Constants.PC_TITLE_MARGIN_TOP,
                  })
                  .textAlign(TextAlign.Center)
                }
              }
              Row() {
                Flex({ justifyContent: FlexAlign.Center }) {
                  Text() {
                    Span(this.content)
                  }
                  .fontSize($r('sys.float.Body_L'))
                  .fontWeight(FontWeight.Medium)
                  .fontColor($r('sys.color.font_primary'))
                  .margin({
                    left: Constants.PC_CONTENT_MARGIN_SIDE,
                    right: Constants.PC_CONTENT_MARGIN_SIDE,
                    top: Constants.PC_CONTENT_MARGIN_TOP
                  })
                }
              }
              Row() {
                Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
                  Button($r('app.string.BAN'))
                    .onClick(async (): Promise<void> => {
                    await this.enableNotification(false);
                    })
                    .customizeButton()
                  Divider()
                    .color($r('sys.color.comp_divider'))
                    .vertical(true)
                    .height(Constants.DIVIDER_HEIGHT)
                    .strokeWidth(Constants.DIVIDER_WIDTH)
                    .margin({left: Constants.BUTTON_LEFT, right: Constants.BUTTON_RIGHT})
                  Button($r('app.string.ALLOW'))
                    .onClick(async (): Promise<void> => {
                      await this.enableNotification(true);
                    })
                    .customizeButton()
                }
                .margin({ 
                  left: Constants.PC_OPERATE_MARGIN_SIDE, 
                  right: Constants.PC_OPERATE_MARGIN_SIDE, 
                  top: Constants.PC_OPERATE_MARGIN_TOP,
                  bottom: Constants.PC_OPERATE_MARGIN_BUTTOM 
                })
              }
            }
          }
          .constraintSize({ maxHeight: Constants.MAXIMUM_HEADER_HEIGHT })
        }
        .borderRadius(Constants.PC_RDIUS_16)
        .backgroundBlurStyle(BlurStyle.COMPONENT_ULTRA_THICK)
        .width(Constants.PC_DIALOG_WIDTH)
        .outline({
            width: 1,
            color: Constants.PC_OUTLINE_COLOR,
            radius: Constants.PC_RDIUS_16
          })
        .clip(true)
      }
      .width(Constants.FULL_WIDTH)
      .height(Constants.FULL_HEIGHT)
    }
  }

  async aboutToAppear(): Promise<void> {
    this.dialog = storage.get('dialog') as EnableNotificationDialog;
    this.session = storage.get('session') as UIExtensionContentSession;
    this.updateAvoidWindow();
    this.updateSubWindowSize();
    try {
      await this.updateStatus();
    } catch (err) {
      console.error(TAG, `aboutToAppear error : ${err?.code}`);
      await this.dialog?.destroyException();
      await this.session?.terminateSelf();
    }
  }

  async aboutToDisappear(): Promise<void> {
    console.info(TAG, `aboutToDisappear`);
    this.session?.terminateSelf();
  }

  async updateOnPageShow(): Promise<void> {
    if (this.isUpdate > 0) {
      await this.updateStatus();
    }
  }

  async updateStatus(): Promise<void> {
    let bundleNameObj = this.dialog?.want.parameters?.bundleName;
    let bundleName = bundleNameObj ? bundleNameObj.toString() : '';
    await this.updateApplicationName(bundleName);
  }

  async updateApplicationName(bundleName: string): Promise<void> {
    console.info(TAG, `updateApplicationName bundleName: ${bundleName}`);
    try {
      let bundleFlags = bundleResourceManager.ResourceFlag.GET_RESOURCE_INFO_ALL;
      let resourceInfo = bundleResourceManager.getBundleResourceInfo(bundleName, bundleFlags);
      console.info(TAG, `applicationName name : ${JSON.stringify(resourceInfo.label)}`);
      let appName = resourceInfo.label;
      this.appName = titleTrim(appName);
      console.info(TAG, `hap label: ${this.appName}`);

      let systemLanguage: string = i18n.System.getSystemLanguage();
      console.info(TAG, `language: ${systemLanguage}`);
      if (systemLanguage.indexOf('zh-Hans')!= -1 ) {
        this.content = LAN_CN;
      } else if (systemLanguage.indexOf('zh-Hant')!= -1 ) {
        this.content = LAN_TW;
      } else if (systemLanguage.indexOf('en')!= -1 ) {
        this.content = LAN_EN;
      } else if (systemLanguage.indexOf('ug')!= -1 ) {
        this.content = LAN_UG;
      } else if (systemLanguage.indexOf('bo')!= -1 ) {
        this.content = LAN_BO;
      }

    } catch (err) {
      console.error(TAG, `applicationName error : ${err?.code}`);
    }
  }

  updateAvoidWindow(): void {
    let type = window.AvoidAreaType.TYPE_SYSTEM;
    try {
      this.dialog?.extensionWindow.on('avoidAreaChange', (data): void => {
        if (data.type == window.AvoidAreaType.TYPE_SYSTEM) {
          console.info(TAG, `avoidAreaChange: ${JSON.stringify(data)}`);
          this.naviHeight = data.area.bottomRect.height;
        }
      });
      let avoidArea = this.dialog?.extensionWindow.getWindowAvoidArea(type);
      if (avoidArea != undefined){
        console.info(TAG, `avoidArea: ${JSON.stringify(avoidArea)}`);
        this.naviHeight = avoidArea.bottomRect.height;
      }
    } catch (err) {
      console.error(TAG, `Failed to obtain the area. Cause: ${err?.code}`);
    }
  }
  
  updateSubWindowSize(): void {
    try {
      this.dialog?.extensionWindow.on('windowSizeChange', (data):void => {
        let windowRect = this.dialog?.extensionWindow.properties?.uiExtensionHostWindowProxyRect;
        console.info(TAG, `windowSizeChange event, size = ${windowRect?.left}-${windowRect?.top}-${windowRect?.width}-${windowRect?.height}`);
        this.dialog?.subWindow?.moveWindowTo(windowRect?.left, windowRect?.top);
        this.dialog?.subWindow?.resize(windowRect?.width, windowRect?.height);
      });
    } catch (err) {
      console.error(TAG, `updateSubWindowSize error. Cause: ${err?.code}`);
    }
  }

  async enableNotification(enabled: boolean): Promise<void> {
    console.info(TAG, `NotificationDialog enableNotification: ${enabled}`);
    try {
      await this.dialog?.publishButtonClickedEvent(enabled);
      this.clicked = true;
    } catch (err) {
      console.error(TAG, `NotificationDialog enable error, code is ${err?.code}`);
      await this.dialog?.destroyException();
    } finally {
      await this.dialog?.subWindow?.destroyWindow();
      this.session?.terminateSelf();
    }
  }
}