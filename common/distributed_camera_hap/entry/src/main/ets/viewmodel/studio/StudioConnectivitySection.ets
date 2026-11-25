/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

import { common } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { AppContext } from '../../common/context/AppContext';
import { AppConstants } from '../../common/constants/AppConstants';
import { PermissionHelper } from '../../common/util/PermissionHelper';
import { CreationSessionState, ScenePrepareResult } from '../../common/types/CreationSessionTypes';
import {
  CameraSourceType,
  CameraTarget,
  StreamSwitchResult,
  StreamSwitchState,
  StreamSwitchType,
  StreamPipelineType,
  StudioMode
} from '../../common/types/CameraTypes';
import {
  SceneTemplate,
  SceneTemplateId
} from '../../common/types/SuperPowerTypes';
import { CameraSessionService } from '../../service/camera/CameraSessionService';
import { PipSessionService } from '../../service/PipSessionService';
import { CreationSessionOrchestrator } from '../../service/CreationSessionOrchestrator';
import { StreamSwitchController } from '../../service/StreamSwitchController';
import { DeviceManagerService } from '../../service/DeviceManagerService';
import { AudioRouteService } from '../../service/AudioRouteService';
import { DistributedHardwareService } from '../../service/DistributedHardwareService';
import {
  DeviceStateChangeEvent,
  DeviceListSource,
  DeviceOnlineState,
  RemotePeerReleaseEvent,
  TrustDeviceInfo
} from '../../common/types/DeviceTypes';
import {
  RemoteConnectKind
} from '../../common/types/RemoteConnectionTypes';
import { RemoteConnectionGuideHelper } from '../../service/RemoteConnectionGuideHelper';
import { PeerSignalService } from '../../service/PeerSignalService';
import { DhDiag } from '../../common/util/DhDiag';
import { CreationIntentExecutor } from '../../service/switch/CreationIntentExecutor';
import { StudioViewModel } from './StudioViewModel';
import { StudioVmUtils } from './StudioVmUtils';

const TAG = AppConstants.TAG;

/** 创作台：切流/引导/画中画/场景 — 从 StudioViewModel 拆出 */
export class StudioConnectivitySection {
  private readonly vm: StudioViewModel;

  constructor(vm: StudioViewModel) {
    this.vm = vm;
  }


  public async refreshCamerasAndHints(): Promise<void> {
    // 冷启动/回创作台仅刷新本机列表，避免 getCameraDevices(REMOTE) 与首开本地预览抢相机
    this.vm.cameras = this.vm.bridgeGetCameraService().enumerateLocalCameras();
    this.updateRemoteFlag();
    this.vm.refreshSuperPowers();
  }

  private updateReadinessHints(): void {
    const boundOnline = this.vm.bridgeGetDmService().getBoundRemoteDevices().filter(
      d => d.state === DeviceOnlineState.ONLINE
    );
    const discovered = this.vm.bridgeGetDmService().getDiscoveredRemoteDevices();
    this.vm.hasBoundRemote = boundOnline.length > 0;
    this.vm.distributedReady = this.vm.bridgeGetDmService().isReady() && this.vm.bridgeGetCameraService().isReady() &&
      this.vm.hasRemoteCamera;

    if (!this.vm.bridgeGetDmService().isReady()) {
      this.vm.localOnlyHint = '设备管理未就绪 · 请授予分布式数据同步权限';
    } else if (!this.vm.hasBoundRemote && discovered.length > 0) {
      this.vm.localOnlyHint =
        `已发现 ${discovered.length} 台对端手机 · 请在设备中心点击「绑定」，` +
        `返回后点场景模板连接（本机拍照/录像仍可用）`;
    } else if (!this.vm.hasBoundRemote) {
      this.vm.localOnlyHint = '暂无对端手机 · 请先在设备中心扫描并绑定' +
        '（本机拍照/录像仍可用）';
    } else if (!this.vm.hasRemoteCamera) {
      const name = boundOnline[0]?.deviceName ?? '对端手机';
      this.vm.localOnlyHint =
        `${name} 已绑定 · 点击上方「双机 Vlog」等场景模板` +
        `连接远端镜头（本机功能仍可用）`;
    } else if (!this.vm.bridgeGetCameraService().isReady()) {
      this.vm.localOnlyHint = '相机未就绪 · 请授予相机权限';
    } else {
      this.vm.localOnlyHint = '';
    }
  }

  public updateRemoteFlag(): void {
    this.vm.hasRemoteCamera = this.vm.cameras.some(c => c.sourceType === CameraSourceType.DISTRIBUTED);
    this.updateReadinessHints();
  }

  /** Index 完成 DM + Studio 初始化后调用，再延迟开预览，避免与 Audio 分布式枚举并发 */
  public markAppBootstrapReady(): void {
    DhDiag.info('BOOT', `markAppBootstrapReady previewReady=${this.vm.surfaceId.length > 0 ? 1 : 0}`);
    this.vm.appBootstrapReady = true;
    this.vm.showRecordingSetup = false;
    this.vm.studioToolsExpanded = false;
    this.vm.studioToolsAutoClosePending = false;
    if (this.vm.surfaceId.length > 0) {
      void this.scheduleBootstrapPreview();
    }
  }

  public setSurfaceId(id: string): void {
    if (id.length === 0) {
      return;
    }
    const prev = this.vm.surfaceId;
    this.vm.surfaceId = id;
    this.vm.bridgeGetCameraService().setSurfaceId(id);
    if (!this.vm.appBootstrapReady) {
      return;
    }
    if (prev === id && !this.vm.appResumingFromBackground) {
      return;
    }
    if (this.vm.bridgeGetCameraService().isActive() && this.vm.activeCamera !== null) {
      void this.resumePreviewAfterSurfaceChange();
      return;
    }
    void this.scheduleBootstrapPreview();
  }

  public onAppBackground(): void {
    this.vm.appInBackground = true;
    if (this.vm.bootstrapPreviewTimer >= 0) {
      clearTimeout(this.vm.bootstrapPreviewTimer);
      this.vm.bootstrapPreviewTimer = -1;
    }
    this.vm.bridgeGetAudioService().suppressPreviewMonitor();
    DhDiag.info('BOOT', 'onAppBackground — keep camera session, pause preview monitor');
  }

  public onAppForeground(): void {
    this.vm.appInBackground = false;
    this.vm.appResumingFromBackground = true;
    if (this.vm.bootstrapPreviewTimer >= 0) {
      clearTimeout(this.vm.bootstrapPreviewTimer);
      this.vm.bootstrapPreviewTimer = -1;
    }
    DhDiag.info('BOOT', `onAppForeground previewReady=${this.vm.surfaceId.length > 0 ? 1 : 0} ` +
      `active=${this.vm.bridgeGetCameraService().isActive() ? 1 : 0}`);
    if (this.vm.isRecordingActive() || this.isSwitchStateBusy()) {
      return;
    }
    this.syncActiveCameraFromService();
    if (this.vm.bridgeGetCameraService().isActive() && this.vm.surfaceId.length > 0) {
      void this.resumePreviewAfterSurfaceChange();
      return;
    }
    if (this.vm.surfaceId.length > 0 && this.vm.activeCamera === null) {
      void this.scheduleBootstrapPreview();
    }
  }

  public async resumePreviewAfterSurfaceChange(): Promise<void> {
    if (this.vm.surfaceRebindInFlight || this.vm.bootstrapPreviewInFlight) {
      return;
    }
    if (this.vm.isRecordingActive() || this.isSwitchStateBusy()) {
      return;
    }
    this.vm.surfaceRebindInFlight = true;
    try {
      this.syncActiveCameraFromService();
      const ok = await this.vm.bridgeGetCameraService().tryRebindPreviewSurface();
      if (ok) {
        this.vm.bridgeRefreshStreamSpecLabels();
        this.schedulePostPreviewCameraControls();
        this.vm.bumpStudioUi();
        if (!this.vm.isRecordingActive() && this.vm.studioMode !== StudioMode.PHOTO) {
          void this.vm.bridgeGetAudioService().ensurePreviewMonitorForStudio();
        }
        DhDiag.info('BOOT', 'resumePreviewAfterSurfaceChange ok');
        return;
      }
      DhDiag.warn('BOOT', 'resumePreviewAfterSurfaceChange failed — fallback bootstrap');
      if (!this.vm.bridgeGetCameraService().isActive()) {
        void this.scheduleBootstrapPreview();
      }
    } finally {
      this.vm.surfaceRebindInFlight = false;
      this.vm.appResumingFromBackground = false;
    }
  }

  private isSwitchStateBusy(): boolean {
    return this.vm.switchState === StreamSwitchState.PREPARING ||
      this.vm.switchState === StreamSwitchState.SWITCHING ||
      this.vm.bridgeGetSwitchController().isSwitchInFlight();
  }

  public lensSwitchBlockedHint(): string {
    if (this.vm.isPreparingScene || this.vm.isConnectingRemote) {
      return '正在连接或准备场景，请稍候再切镜头';
    }
    if (this.isSwitchStateBusy()) {
      return '正在切流，请稍候';
    }
    return '';
  }

  public syncActiveCameraFromService(): void {
    const serviceTarget = this.vm.bridgeGetCameraService().getCurrentTarget();
    if (serviceTarget) {
      this.vm.activeCamera = serviceTarget;
      return;
    }
    const current = this.vm.bridgeGetSwitchController().getLastActiveTarget();
    if (current) {
      this.vm.activeCamera = current;
    }
  }

  public async scheduleBootstrapPreview(): Promise<void> {
    if (this.vm.bootstrapPreviewInFlight) {
      DhDiag.flowEnd('BOOT', 'bootstrapPreview', false, 'skip — in-flight');
      return;
    }
    if (this.vm.bootstrapPreviewTimer >= 0 && !this.vm.appResumingFromBackground) {
      DhDiag.info('BOOT', 'bootstrapPreview coalesce — timer pending');
      return;
    }
    DhDiag.flowBegin('BOOT', 'bootstrapPreview',
        `delay=${AppConstants.BOOTSTRAP_PREVIEW_DELAY_MS}ms ` +
        `active=${this.vm.bridgeGetCameraService().isActive() ? 1 : 0}`);
    if (this.vm.bridgeGetCameraService().isActive()) {
      this.syncActiveCameraFromService();
      if (this.vm.surfaceId.length > 0 && !this.vm.surfaceRebindInFlight) {
        void this.resumePreviewAfterSurfaceChange();
      } else {
        this.vm.bridgeRefreshStreamSpecLabels();
        this.schedulePostPreviewCameraControls();
      }
      DhDiag.flowEnd('BOOT', 'bootstrapPreview', true,
        `skip cold open — session active vm=${this.vm.activeCamera?.cameraId ?? 'none'}`);
      return;
    }
    if (this.isSwitchStateBusy()) {
      return;
    }
    const ctx = AppContext.tryGet();
    if (ctx) {
      const granted = await PermissionHelper.requestRequiredPermissions(ctx);
      if (!granted) {
        DhDiag.flowEnd('BOOT', 'bootstrapPreview', false, 'camera permission denied');
        this.vm.mediaHint = '需要相机权限才能预览';
        this.vm.bumpStudioUi();
        return;
      }
    }
    if (this.vm.bootstrapPreviewTimer >= 0) {
      clearTimeout(this.vm.bootstrapPreviewTimer);
      this.vm.bootstrapPreviewTimer = -1;
    }
    const delayMs = this.vm.appResumingFromBackground ?
      AppConstants.RESUME_PREVIEW_DELAY_MS : AppConstants.BOOTSTRAP_PREVIEW_DELAY_MS;
    this.vm.appResumingFromBackground = false;
    if (delayMs > 0) {
      await new Promise<void>(resolve => {
        this.vm.bootstrapPreviewTimer = setTimeout(() => {
          this.vm.bootstrapPreviewTimer = -1;
          resolve();
        }, delayMs) as number;
      });
    }
    if (this.vm.bridgeGetCameraService().isActive() || this.isSwitchStateBusy()) {
      return;
    }
    let local = this.vm.bridgeGetCameraService().findLocalCameraTarget('back') ??
      this.vm.cameras.find(c => c.sourceType === CameraSourceType.LOCAL && c.position === 'back') ??
      this.vm.bridgeGetCameraService().enumerateLocalCameras().find(c => c.position === 'back');
    if (!local) {
      DhDiag.warn('BOOT', 'bootstrapPreview — back camera missing, try front');
      local = this.vm.bridgeGetCameraService().findLocalCameraTarget('front') ??
        this.vm.cameras.find(c => c.sourceType === CameraSourceType.LOCAL && c.position === 'front');
    }
    if (!local) {
      DhDiag.flowEnd('BOOT', 'bootstrapPreview', false, 'no local camera');
      return;
    }
    this.vm.bootstrapPreviewInFlight = true;
    this.vm.bridgeGetCameraService().setDeferSessionCameraControls(true);
    try {
      await this.openBootstrapPreviewDirect(local);
      this.vm.bumpStudioUi();
      DhDiag.flowEnd('BOOT', 'bootstrapPreview', this.vm.switchState === StreamSwitchState.ACTIVE,
        `state=${this.vm.switchState} cameraId=${local.cameraId}`);
    } catch (err) {
      DhDiag.logCatchWarn('BOOT', 'bootstrapPreview', err);
      this.vm.fallbackHint = '预览启动异常，请稍后重试';
    } finally {
      this.vm.bootstrapPreviewInFlight = false;
      this.vm.bridgeGetCameraService().setDeferSessionCameraControls(false);
      this.schedulePostPreviewCameraControls();
      DhDiag.info('BOOT', 'bootstrapPreview finally — event loop should resume');
      setTimeout(() => {
        DhDiag.info('BOOT', 'post-bootstrap macrotask fired');
      }, 0) as number;
    }
  }

  /**
    * 冷启动首开：直连 CameraSession，不经 switchStream 状态机
    * （避免 preparing→switching→active 连击卡死主线程）
   */
  private async openBootstrapPreviewDirect(local: CameraTarget): Promise<void> {
    DhDiag.flowStep('BOOT', 'bootstrapPreview', 'directOpen', `id=${local.cameraId}`);
    this.vm.bridgeGetCameraService().resetSpecChangeGate();
    const t0 = Date.now();
    const ok = await this.vm.bridgeGetCameraService().openAndPreview(local, StudioMode.PREVIEW,
      StreamPipelineType.CONTINUOUS, true);
    const elapsed = Date.now() - t0;
    DhDiag.info('BOOT', `directOpen exit ok=${ok ? 1 : 0} elapsed=${elapsed}ms`);
    if (!ok) {
      DhDiag.warn('BOOT', `directOpen failed — fallback switchStream` +
        ` | ${this.vm.bridgeGetCameraService().getLastOpenErrorMessage()}`);
      this.vm.suppressPreviewMonitorOnce = true;
      await this.selectCamera(local, StreamSwitchType.LOCAL_REMOTE);
      return;
    }
    this.vm.bridgeGetSwitchController().commitBootstrapPreview(
      local, StudioMode.PREVIEW, StreamPipelineType.CONTINUOUS);
    this.vm.suppressPreviewMonitorOnce = true;
    const result: StreamSwitchResult = {
      success: true,
      switchType: StreamSwitchType.LOCAL_REMOTE,
      target: local,
      elapsedMs: elapsed,
      firstFrameMs: elapsed
    };
    await this.applySwitchResult(result);
  }

  private schedulePostPreviewCameraControls(): void {
    if (this.vm.postPreviewControlsTimer >= 0) {
      clearTimeout(this.vm.postPreviewControlsTimer);
    }
    this.vm.postPreviewControlsTimer = setTimeout(() => {
      this.vm.postPreviewControlsTimer = -1;
      DhDiag.info('BOOT', 'postPreviewCameraControls apply');
      this.vm.bridgeGetCameraService().applySessionCameraControlsNow();
      this.vm.bridgeRefreshStreamSpecLabels();
      this.vm.refreshSuperPowers();
      this.vm.bumpStudioUi();
    }, AppConstants.CAMERA_CONTROLS_PROBE_DELAY_MS) as number;
  }

  private scheduleDeferredBootstrapUiRefresh(): void {
    this.schedulePostPreviewCameraControls();
  }

  public setPipSurfaceId(id: string): void {
    this.vm.bridgeGetPipService().setSurfaceId(id);
    if (this.vm.pipOverlayVisible && this.vm.activeCamera) {
      this.refreshPipOverlay();
    }
  }

  /** 画中画开关 — 仅按钮触发，不随主镜头切换自动打开 */
  public async togglePipOverlay(): Promise<void> {
    if (this.vm.pipOverlayVisible) {
      await this.vm.bridgeClosePipOverlay();
      this.vm.mediaHint = '已关闭画中画';
      return;
    }
    await this.openPipOverlay();
  }

  private async openPipOverlay(): Promise<void> {
    if (!this.vm.activeCamera) {
      this.vm.fallbackHint = '请先点机位按钮选择主镜头（本机/远端 前摄或后摄）';
      return;
    }
    if (!this.vm.hasBoundRemote || !this.vm.hasRemoteCamera) {
      this.vm.fallbackHint = '画中画需先在设备中心绑定对端并连接远端镜头';
      return;
    }
    this.vm.pipOverlayVisible = true;
    await this.refreshPipOverlay();
    if (this.vm.pipPreviewActive) {
      this.vm.mediaHint = '画中画已开 · 小窗为互补镜头 · 主画面切换机位可继续预览/录像';
      this.vm.fallbackHint = '';
    } else {
      this.vm.fallbackHint = this.vm.pipPreviewHint || '画中画打开失败';
      this.vm.pipOverlayVisible = false;
    }
  }

  public async closePipOverlay(): Promise<void> {
    try {
      if (this.vm.bridgeGetPipService().isPipRecording()) {
        const pipSaved = await this.vm.bridgeGetPipService().stopRecording(true);
        this.vm.pipRecordingActive = false;
        if (pipSaved?.success) {
          this.vm.mediaHint = `辅路已单独保存 · ${pipSaved.message}`;
        }
      }
      this.vm.pipOverlayVisible = false;
      await this.vm.bridgeGetPipService().close();
      this.vm.pipCamera = null;
      this.vm.pipPreviewActive = false;
      this.vm.pipPreviewHint = '';
    } catch (err) {
      DhDiag.logCatchWarn('PIP', 'closePipOverlay', err);
      this.vm.pipOverlayVisible = false;
      this.vm.pipPreviewActive = false;
      this.vm.fallbackHint = '关闭画中画异常';
    }
  }

  /** 画中画已开时，主镜头切换后刷新小窗为新的互补机位 */
  public async refreshPipIfOpen(): Promise<void> {
    if (!this.vm.pipOverlayVisible) {
      return;
    }
    await this.refreshPipOverlay();
  }

  private async refreshPipOverlay(): Promise<void> {
    if (!this.vm.pipOverlayVisible || !this.vm.activeCamera) {
      return;
    }
    if (this.vm.isRecordingActive() || this.vm.bridgeGetPipService().isPipRecording()) {
      return;
    }
    const pipTarget = PipSessionService.resolveComplementTarget(this.vm.activeCamera, this.vm.cameras);
    if (!pipTarget) {
      this.vm.pipPreviewHint = '无互补镜头';
      this.vm.pipPreviewActive = false;
      return;
    }
    if (PipSessionService.isDualSessionLikelyBlocked(this.vm.activeCamera, pipTarget)) {
      DhDiag.warn('PIP', 'dual session local+remote — may hit 7400102/7400107 on this device');
    }
    await StudioVmUtils.bridgeDelay(400);
    try {
      const ok = await this.vm.bridgeGetPipService().open(pipTarget);
      this.vm.pipCamera = pipTarget;
      this.vm.pipPreviewActive = ok;
      if (!ok && PipSessionService.isDualSessionLikelyBlocked(this.vm.activeCamera, pipTarget)) {
        this.vm.pipPreviewHint = `${this.vm.bridgeGetPipService().getLastError()}` +
          ` · 双机模式系统常不支持主辅两路相机同时开`;
      } else {
        this.vm.pipPreviewHint = ok ? '' : (this.vm.bridgeGetPipService().getLastError() || '辅画面打开失败');
      }
      if (!ok) {
        DhDiag.warn('PIP', `refreshPipOverlay failed ${this.vm.pipPreviewHint}`);
      }
    } catch (err) {
      DhDiag.logCatchWarn('PIP', 'refreshPipOverlay', err);
      this.vm.pipPreviewActive = false;
      this.vm.pipPreviewHint = '辅画面打开异常';
    }
  }

  public async selectCamera(target: CameraTarget, type: StreamSwitchType): Promise<void> {
    DhDiag.flowStep('VM', 'selectCamera', 'invoke',
      `type=${type} id=${target.cameraId} src=${target.sourceType}`);
    const result = await this.vm.bridgeGetSwitchController().switchStream(type, target);
    await this.applySwitchResult(result);
  }

  public async switchToRemote(position: string = 'back'): Promise<void> {
    await this.connectRemoteCamera(position);
  }

  /** 带分步引导的连接对端镜头 */
  public async connectRemoteCamera(position: string = 'back'): Promise<void> {
    await CreationIntentExecutor.runPreviewConnect(this.vm.buildPreviewConnectHost(), position);
  }

  public async retryConnectRemoteCamera(position: string = 'back'): Promise<void> {
    this.vm.remoteGuideFailed = false;
    await this.connectRemoteCamera(position);
  }

  public dismissRemoteGuide(): void {
    this.vm.showRemoteGuide = false;
    this.vm.remoteGuideFailed = false;
    this.vm.isConnectingRemote = false;
    this.vm.bumpStudioUi();
  }

  /** 机位切换：先收起「机位·模式」面板，露出预览区切流遮罩 */
  private collapseToolsForLensSwitch(): void {
    this.vm.keepStudioToolsOpen = false;
    this.vm.studioToolsAutoClosePending = false;
    if (this.vm.studioToolsExpanded) {
      DhDiag.info('FLOW', 'collapseToolsForLensSwitch');
      this.closeStudioTools();
    }
    this.vm.bumpStudioUi();
  }

  public getPrimaryBoundPeer(): TrustDeviceInfo | null {
    const list = this.vm.bridgeGetDmService().getBoundRemoteDevices().filter(
      d => d.state === DeviceOnlineState.ONLINE && d.listSource === DeviceListSource.TRUSTED);
    if (list.length === 0) {
      return null;
    }
    if (this.vm.preferredRemoteNetworkId.length > 0) {
      const preferred = list.find(d =>
        CameraSessionService.networkIdMatches(d.networkId, this.vm.preferredRemoteNetworkId));
      if (preferred) {
        return preferred;
      }
    }
    const active = this.vm.activeCamera ?? this.vm.bridgeGetCameraService().getCurrentTarget();
    if (active?.sourceType === CameraSourceType.DISTRIBUTED && active.networkId) {
      const onActive = list.find(d =>
        CameraSessionService.networkIdMatches(d.networkId, active.networkId ?? ''));
      if (onActive) {
        return onActive;
      }
    }
    for (const peer of list) {
      if (this.vm.bridgeGetCameraService().findRemoteCameraDevice(peer.networkId, 'back') ||
        this.vm.bridgeGetCameraService().findRemoteCameraDevice(peer.networkId, 'front')) {
        DhDiag.info('CONNECT', `getPrimaryBoundPeer pick=${peer.deviceName} — CF REMOTE visible`);
        return peer;
      }
    }
    if (list.length > 1) {
      DhDiag.warn('CONNECT',
        `getPrimaryBoundPeer fallback ${list[0].deviceName} ` +
        `among ${list.length} — 请在设备中心对目标设备点「设为镜头」`);
    }
    return list[0];
  }

  /** 设备中心「设为镜头」→ 跳转创作台并切到指定对端后摄
   * （前/后在创作台工具面板切换） */
  public async setLensFromDeviceCenter(networkId: string, position: string = 'back'): Promise<void> {
    this.vm.preferredRemoteNetworkId = networkId;
    DhDiag.info('DC', `setLensFromDeviceCenter net=${networkId.substring(0, 12)}... pos=${position}`);
    const blocked = this.lensSwitchBlockedHint();
    if (blocked.length > 0) {
      this.vm.fallbackHint = blocked;
      this.vm.mediaHint = blocked;
      return;
    }
    this.vm.bridgeGetSwitchController().prepareRetryFromError();
    const active = this.vm.activeCamera;
    if (active?.sourceType === CameraSourceType.DISTRIBUTED &&
      CameraSessionService.networkIdMatches(active.networkId ?? '', networkId) &&
      active.position === position) {
      this.vm.mediaHint = `已是 ${active.deviceName} ${position === 'front' ? '前摄' : '后摄'}`;
      return;
    }
    if (active?.sourceType === CameraSourceType.DISTRIBUTED &&
      CameraSessionService.networkIdMatches(active.networkId ?? '', networkId)) {
      this.vm.mediaHint = `正在切到远端${position === 'front' ? '前' : '后'}摄…`;
      await this.vm.switchLens(position);
      return;
    }
    this.vm.setPendingLens('remote', position);
    this.vm.mediaHint = '⏳ 正在连接所选对端镜头…';
    this.collapseToolsForLensSwitch();
    await this.connectRemoteCamera(position);
  }

  public getPeerStandbyMessage(): string {
    const bound = this.vm.bridgeGetDmService().getBoundRemoteDevices();
    if (bound.length === 0) {
      return '';
    }
    const names = bound.map(d => d.deviceName).join('、');
    return `已绑定 ${names}。导播连镜头时请保持本应用前台 · 系统弹窗出现时请允许相机。`;
  }

  public async switchToRemoteDevice(networkId: string, position: string = 'back'): Promise<void> {
    const result = await this.vm.bridgeGetSwitchController().switchToRemoteDevice(networkId, position);
    await this.applySwitchResult(result);
  }

  public async connectOrSwitchRemote(position: string): Promise<void> {
    const blocked = this.lensSwitchBlockedHint();
    if (blocked.length > 0) {
      this.vm.fallbackHint = blocked;
      this.vm.mediaHint = blocked;
      return;
    }
    this.vm.bridgeGetSwitchController().prepareRetryFromError();
    const peer = this.getPrimaryBoundPeer();
    if (!peer) {
      this.vm.fallbackHint = '无在线对端设备 · 请先在设备中心绑定，' +
        '或对目标设备点「设为镜头」';
      return;
    }
    const active = this.vm.activeCamera ?? this.vm.bridgeGetCameraService().getCurrentTarget();
    const onTargetPeer = active?.sourceType === CameraSourceType.DISTRIBUTED &&
      CameraSessionService.networkIdMatches(active.networkId ?? '', peer.networkId);
    if (onTargetPeer && active !== null && active.position === position) {
      DhDiag.info('FLOW', `connectOrSwitchRemote skip — already on ${peer.deviceName} remote ${position}`);
      this.vm.mediaHint = `已是 ${peer.deviceName} ${position === 'front' ? '前摄' : '后摄'}`;
      return;
    }
    this.vm.setPendingLens('remote', position);
    if (onTargetPeer) {
      this.vm.mediaHint = `⏳ 正在切到 ${peer.deviceName} ${position === 'front' ? '前' : '后'}摄…`;
      this.collapseToolsForLensSwitch();
      await this.vm.switchLens(position);
      return;
    }
    this.vm.mediaHint = `⏳ 正在连接 ${peer.deviceName} 远端${position === 'front' ? '前' : '后'}摄…`;
    this.collapseToolsForLensSwitch();
    await this.connectRemoteCamera(position);
    if (this.vm.activeCamera !== null) {
      this.vm.keepStudioToolsOpen = false;
    }
  }

  public async connectOrSwitchLocal(position: string): Promise<void> {
    const blocked = this.lensSwitchBlockedHint();
    if (blocked.length > 0) {
      this.vm.fallbackHint = blocked;
      this.vm.mediaHint = blocked;
      return;
    }
    this.vm.bridgeGetSwitchController().prepareRetryFromError();
    this.syncActiveCameraFromService();
    const live = this.vm.bridgeGetCameraService().getCurrentTarget();
    const active = live ?? this.vm.activeCamera;
    const livePos = live?.position ?? active?.position ?? '';
    if (active?.sourceType === CameraSourceType.LOCAL && livePos === position &&
      this.vm.bridgeGetCameraService().isActive()) {
      DhDiag.info('FLOW', `connectOrSwitchLocal skip — already on local ${position}`);
      this.vm.activeCamera = active;
      this.vm.mediaHint = `已是本机${position === 'front' ? '前' : '后'}摄`;
      this.vm.bumpStudioUi();
      return;
    }
    this.vm.setPendingLens('local', position);
    if (active?.sourceType === CameraSourceType.LOCAL) {
      this.vm.mediaHint = `⏳ 正在切到本机${position === 'front' ? '前' : '后'}摄…`;
      this.collapseToolsForLensSwitch();
      await this.vm.switchLens(position);
      return;
    }
    const leavingRemote = active?.sourceType === CameraSourceType.DISTRIBUTED;
    if (leavingRemote) {
      DhDiag.info('FLOW', 'connectOrSwitchLocal: leaving remote → local');
      this.vm.mediaHint = '⏳ 正在切回本机镜头…';
    } else {
      this.vm.mediaHint = `⏳ 正在切到本机${position === 'front' ? '前' : '后'}摄…`;
    }
    this.collapseToolsForLensSwitch();
    let local = this.vm.bridgeGetCameraService().findLocalCameraTarget(position);
    if (!local) {
      const locals = this.vm.bridgeGetCameraService().enumerateLocalCameras();
      local = locals.find(c => c.position === position) ?? null;
    }
    if (!local) {
      this.vm.cameras = await this.vm.bridgeGetCameraService().enumerateCameras(true);
      local = this.vm.bridgeGetCameraService().findLocalCameraTarget(position) ??
        this.vm.cameras.find(c => c.sourceType === CameraSourceType.LOCAL && c.position === position) ?? null;
    }
    if (!local) {
      this.vm.fallbackHint = `本机${position === 'front' ? '前' : '后'}摄不可用` +
        ` · 请确认未占用画中画或录像`;
      this.vm.mediaHint = this.vm.fallbackHint;
      this.openStudioTools();
      return;
    }
    this.vm.fallbackHint = '';
    const switchMode = this.vm.bridgeGetCameraService().isRecording() ? this.vm.studioMode : StudioMode.PREVIEW;
    try {
      const result = await this.vm.bridgeGetSwitchController().switchStream(
        StreamSwitchType.LOCAL_REMOTE, local, switchMode);
      await this.applySwitchResult(result);
      if (result.success && switchMode === StudioMode.PREVIEW && this.vm.studioMode === StudioMode.VIDEO &&
        !this.vm.bridgeGetCameraService().isRecording()) {
        this.vm.studioMode = StudioMode.PREVIEW;
      }
      if (!result.success) {
        this.openStudioTools();
        this.syncActiveCameraFromService();
      }
    } finally {
      this.syncActiveCameraFromService();
      this.vm.bumpStudioUi();
    }
  }

  public async switchLens(position: string): Promise<void> {
    const active = this.vm.activeCamera;
    if (active?.sourceType === CameraSourceType.DISTRIBUTED) {
      this.vm.setPendingLens('remote', position);
    } else if (active?.sourceType === CameraSourceType.LOCAL) {
      this.vm.setPendingLens('local', position);
    }
    this.collapseToolsForLensSwitch();
    if (!active) {
      if (this.vm.hasBoundRemote) {
        await this.connectRemoteCamera(position);
        return;
      }
      const result = await this.vm.bridgeGetSwitchController().switchLensOnActiveDevice(position);
      await this.applySwitchResult(result);
      return;
    }
    if (active.sourceType === CameraSourceType.DISTRIBUTED) {
      const result = await this.vm.bridgeGetSwitchController().switchRemoteLens(position);
      await this.applySwitchResult(result);
      if (result.success) {
        this.vm.bridgeGetCameraService().enumerateCameras(true).then(list => {
          this.vm.cameras = list;
          this.updateRemoteFlag();
        }).catch((err: Error) => {
          DhDiag.warn('VM', `enumerateCameras after remote lens switch failed ${JSON.stringify(err)}`);
        });
      }
      return;
    }
    const result = await this.vm.bridgeGetSwitchController().switchLensOnActiveDevice(position);
    await this.applySwitchResult(result);
  }

  /** 场景模板就绪后 — 同步机位 Chip、预览标签、声场摘要、Sync 开关 */
  private syncUiAfterSceneReady(result: ScenePrepareResult, template: SceneTemplate): void {
    const target = result.mainTarget ?? this.vm.bridgeGetSwitchController().getLastActiveTarget();
    if (target) {
      this.vm.activeCamera = target;
      this.vm.hasSwitchedStream = true;
      if (target.sourceType === CameraSourceType.DISTRIBUTED) {
        this.vm.remoteSessionEstablished = true;
      }
    }
    this.vm.sessionSummary = this.vm.bridgeGetOrchestrator().getSessionSummary();
    const camLabel = target ?
        `${target.sourceType === CameraSourceType.DISTRIBUTED ? '远端' : '本机'}` +
        `${target.position === 'front' ? '前摄' : '后摄'}` :
      '主镜头';
    this.vm.bridgePublishAudioRouteReadyHint();
    const routeHint = this.vm.bridgeGetAudioService().getLastRouteError();
    this.vm.mediaHint = routeHint.length > 0 ?
      `✓ ${template.title} · ${camLabel} · ${this.vm.remoteMicStatusHint}（${routeHint}）` :
      `✓ ${template.title} · ${camLabel} · ${this.vm.remoteMicStatusHint}`;
    this.vm.fallbackHint = '';
    this.vm.bridgeRefreshStreamSpecLabels();
    this.refreshPipIfOpen();
    void this.vm.bridgeGetAudioService().restartPreviewMonitor().then(() => {
      this.vm.bridgePublishAudioRouteReadyHint();
      this.vm.recordingUiTick++;
    }).catch((err: Error) => {
      DhDiag.warn('VM', `restartPreviewMonitor after scene ready failed ${JSON.stringify(err)}`);
    });
  }


  public openStudioTools(): void {
    DhDiag.info('VM', 'openStudioTools');
    this.vm.studioToolsExpanded = true;
    this.vm.bridgeGetCameraService().applySessionCameraControlsNow();
    this.vm.bridgeRefreshStreamSpecLabels();
    this.vm.bumpStudioUi();
  }

  public closeStudioTools(): void {
    DhDiag.info('VM', 'closeStudioTools');
    this.vm.studioToolsExpanded = false;
    this.vm.studioToolsAutoClosePending = false;
    this.vm.keepStudioToolsOpen = false;
    this.vm.bumpStudioUi();
  }

  public toggleStudioTools(): void {
    this.vm.studioToolsExpanded = !this.vm.studioToolsExpanded;
    if (!this.vm.studioToolsExpanded) {
      this.vm.keepStudioToolsOpen = false;
    }
    DhDiag.info('VM', `toggleStudioTools expanded=${this.vm.studioToolsExpanded ? 1 : 0}`);
    if (this.vm.studioToolsExpanded) {
      this.vm.bridgeGetCameraService().applySessionCameraControlsNow();
      this.vm.bridgeRefreshStreamSpecLabels();
      const peer = this.getPrimaryBoundPeer();
      if (peer && this.vm.activeCamera?.sourceType !== CameraSourceType.DISTRIBUTED) {
        const camSvc = this.vm.bridgeGetCameraService();
        const remoteVisible = camSvc.findRemoteCameraDevice(peer.networkId, 'back') !== null ||
          camSvc.findRemoteCameraDevice(peer.networkId, 'front') !== null;
        if (!remoteVisible) {
          this.vm.bridgeGetDhService().prewarmRemoteCamera(peer.networkId);
        } else {
          DhDiag.info('VM', 'toggleStudioTools skip prewarm — CF REMOTE already enumerated');
        }
      }
    } else {
      this.vm.studioToolsAutoClosePending = false;
    }
    this.vm.bumpStudioUi();
  }

  /** 底栏摘要：当前机位，点击可展开工具面板 */
  public activeLensShortLabel(): string {
    if (!this.vm.activeCamera) {
      return '未选机位';
    }
    const cam = this.vm.activeCamera;
    const src = cam.sourceType === CameraSourceType.DISTRIBUTED ? '远端' : '本机';
    return `${src}${cam.position === 'front' ? '前' : '后'}`;
  }

  public async applySwitchResult(result: StreamSwitchResult): Promise<void> {
    if (result.success) {
      this.vm.activeCamera = result.target;
      DhDiag.flowStep('VM', 'applySwitchResult', 'ok',
        `cameraId=${this.vm.activeCamera?.cameraId ?? result.target.cameraId} ` +
        `elapsed=${result.elapsedMs}ms firstFrame=${result.firstFrameMs}ms`);
      this.vm.firstFrameMs = result.firstFrameMs;
      this.vm.switchElapsedMs = result.elapsedMs;
      this.vm.hasSwitchedStream = true;
      this.vm.fallbackHint = '';
      this.vm.mediaHint = `已切到` +
        `${result.target.sourceType === CameraSourceType.DISTRIBUTED ? '远端' : '本机'}` +
        `${result.target.position === 'front' ? '前摄' : '后摄'}`;
      if (result.target.sourceType === CameraSourceType.DISTRIBUTED && result.target.networkId) {
        const netId = result.target.networkId;
        void StudioVmUtils.bridgeDelay(2500).then(() => {
          if (this.vm.activeCamera?.networkId === netId) {
            this.prewarmRemoteRecordingMic(netId);
          }
        }).catch((err: Error) => {
          DhDiag.warn('VM', `prewarmRemoteRecordingMic delay failed ${JSON.stringify(err)}`);
        });
      }
      const bootstrapUi = this.vm.suppressPreviewMonitorOnce;
      if (bootstrapUi) {
        this.vm.suppressPreviewMonitorOnce = false;
        DhDiag.info('BOOT', 'applySwitchResult bootstrap — defer camera controls refresh');
        // 规格选项立即可用，避免冷启动 Select 长期显示「无可用分辨率」
        this.vm.bridgeRefreshStreamSpecLabelsForRecordingSetup();
        DhDiag.info('BOOT',
          `bootstrap streamSpec eager refresh res=${this.vm.streamResolutionOptions.length} ` +
          `fps=${this.vm.streamFpsOptions.length} camera=${this.vm.activeCamera?.cameraId ?? 'none'}`);
        this.schedulePostPreviewCameraControls();
      } else {
        this.vm.bridgeRefreshStreamSpecLabels();
        this.vm.refreshSuperPowers();
        this.schedulePostPreviewCameraControls();
      }
      void this.refreshPipIfOpen();
      if (bootstrapUi) {
        DhDiag.info('BOOT', 'applySwitchResult skip preview monitor — bootstrap');
      } else if (this.vm.studioMode !== StudioMode.PHOTO) {
        void StudioVmUtils.bridgeDelay(1000).then(() => {
          void this.vm.bridgeGetAudioService().ensurePreviewMonitorForStudio();
        }).catch((err: Error) => {
          DhDiag.warn('VM', `ensurePreviewMonitorForStudio delay failed ${JSON.stringify(err)}`);
        });
      }
      if (this.vm.studioToolsExpanded && !this.vm.keepStudioToolsOpen) {
        this.vm.closeStudioTools();
      }
      this.vm.clearPendingLens();
      this.vm.bumpStudioUi();
    } else if (result.errorMessage) {
      DhDiag.flowStep('VM', 'applySwitchResult', 'fail', result.errorMessage);
      this.vm.fallbackHint = result.errorMessage;
      this.vm.mediaHint = result.errorMessage;
      this.vm.clearPendingLens();
      const camService = this.vm.bridgeGetCameraService();
      const current = camService.getCurrentTarget() ??
        this.vm.bridgeGetSwitchController().getLastActiveTarget();
      if (current) {
        this.vm.activeCamera = current;
      }
      this.vm.bumpStudioUi();
    }
  }

  /** 一键准备双机场景 — 创作会话引擎入口 */
  public async applySceneTemplate(template: SceneTemplate): Promise<void> {
    const applyGen = ++this.vm.sceneApplyGeneration;
    this.vm.bridgeGetOrchestrator().abortScenePrepare();
    PeerSignalService.getInstance().stopHeartbeat();
    if (!this.vm.isRecordingActive()) {
      this.vm.bridgeGetAudioService().cancelRecordingRemoteMicSetup();
      this.vm.bridgeGetAudioService().resumePreviewMonitor();
    }

    this.vm.selectedSceneId = template.id;
    const peer = this.getPrimaryBoundPeer();
    if (peer) {
      this.vm.remotePeerDeviceName = peer.deviceName;
      this.vm.remoteGuideTitle = `正在准备：${template.title}`;
      let guideKind = RemoteConnectKind.SCENE;
      if (template.id === SceneTemplateId.DUAL_VLOG_REMOTE_MIC) {
        guideKind = RemoteConnectKind.AUDIO_MIC;
        PeerSignalService.getInstance().publishMicRequest(peer.deviceName);
        this.vm.remoteGuideProgress = '对端收音：请在对端 App 查看' +
          '「远端收音请求」并允许麦克风…';
      } else if (template.id === SceneTemplateId.DUAL_VLOG_REMOTE_SPK) {
        guideKind = RemoteConnectKind.AUDIO_SPEAKER;
        PeerSignalService.getInstance().publishSceneRequest(peer.deviceName);
        this.vm.remoteGuideProgress = '对端外放：请在对端允许相机与音频相关授权…';
      } else {
        PeerSignalService.getInstance().publishSceneRequest(peer.deviceName);
        this.vm.remoteGuideProgress = '连接远端镜头（约 6s 内完成探测）…';
      }
      this.vm.remoteGuideSteps = RemoteConnectionGuideHelper.buildSceneSteps(peer.deviceName, guideKind);
      this.vm.showRemoteGuide = true;
      this.vm.isConnectingRemote = true;
    }
    this.vm.isPreparingScene = true;
    this.vm.fallbackHint = '';
    this.vm.mediaHint = `正在准备：${template.title}…`;
    hilog.info(AppConstants.LOG_DOMAIN, TAG, 'applyScene: %{public}s', template.id);
    DhDiag.info('SCENE', `applySceneTemplate ${template.id} gen=${applyGen}`);
    const result = await this.vm.bridgeGetOrchestrator().prepareScene(template.id);
    PeerSignalService.getInstance().stopHeartbeat();
    if (applyGen !== this.vm.sceneApplyGeneration) {
      return;
    }
    this.vm.isPreparingScene = false;
    this.vm.closeStudioTools();
    if (result.success) {
      this.vm.cameras = await this.vm.bridgeGetCameraService().enumerateCameras(true);
      this.updateRemoteFlag();
      this.syncUiAfterSceneReady(result, template);
      this.vm.refreshSuperPowers();
      if (this.vm.showRemoteGuide) {
        this.vm.remoteGuideSteps = RemoteConnectionGuideHelper.markAllDone(this.vm.remoteGuideSteps);
        this.vm.remoteGuideProgress = '✓ 双机场景已就绪';
        this.vm.remoteGuideFailed = false;
        await StudioVmUtils.bridgeDelay(2500);
        this.vm.showRemoteGuide = false;
      }
    } else {
      this.vm.fallbackHint = result.message;
      if (this.vm.showRemoteGuide) {
        this.vm.remoteGuideFailed = true;
        this.vm.remoteGuideSteps = RemoteConnectionGuideHelper.markAllFailed(this.vm.remoteGuideSteps, 'connect');
        this.vm.remoteGuideProgress = `${result.message} · 可点「重试」`;
      }
    }
    this.vm.isConnectingRemote = false;
  }

  public async switchToLocal(): Promise<void> {
    const result = await this.vm.bridgeGetSwitchController().fallbackToLocal();
    await this.applySwitchResult(result);
  }

  /** 设备中心解绑 / 账号设备应用层 detach — 重置远端会话标记并回退本机 */
  public async onRemotePeerReleased(networkId: string, deviceId: string): Promise<void> {
    DhDiag.flowBegin('VM', 'onRemotePeerReleased',
      `net=${networkId.substring(0, 12)}... dev=${deviceId.substring(0, 12)}...`);
    this.vm.remoteSessionEstablished = false;
    this.vm.coldReconnectAfterPeerRelease = true;
    this.dismissRemoteGuide();
    this.vm.clearPendingLens();
    if (this.vm.preferredRemoteNetworkId.length > 0 &&
      CameraSessionService.networkIdMatches(this.vm.preferredRemoteNetworkId, networkId)) {
      this.vm.preferredRemoteNetworkId = '';
    }
    const active = this.vm.activeCamera;
    const affectsActive = active !== null &&
      active.sourceType === CameraSourceType.DISTRIBUTED &&
      (CameraSessionService.networkIdMatches(active.networkId ?? '', networkId) ||
        CameraSessionService.networkIdMatches(active.deviceId, deviceId) ||
        CameraSessionService.networkIdMatches(active.cameraId, networkId));
    if (affectsActive) {
      if (this.vm.isRecordingActive()) {
        await this.vm.stopOrCancelRecording();
      }
      this.vm.showRecordingSetup = false;
      const fb = await this.vm.bridgeGetSwitchController().fallbackToLocal();
      await this.applySwitchResult(fb);
      this.vm.fallbackHint = '已解除对端镜头关联 · 已回退本机预览';
    } else {
      await this.refreshCamerasAndHints();
    }
    DhDiag.flowEnd('VM', 'onRemotePeerReleased', true, `affectsActive=${affectsActive ? 1 : 0}`);
  }

  /** 连上远端主镜头后后台预配麦，缩短点录像时的「准备」等待 */
  public prewarmRemoteRecordingMic(networkId: string): void {
    if (this.vm.bridgeGetAudioService().isRemoteMicRouted(networkId)) {
      this.vm.remoteMicStatusHint = '✓ 对端麦克风已就绪，开录将直接收录对端声音';
      this.vm.recordingUiTick++;
      return;
    }
    const peer = this.getPrimaryBoundPeer();
    this.vm.remoteMicStatusHint = '⏳ 正在后台配置对端麦克风…';
    this.vm.recordingUiTick++;
    void this.vm.bridgeGetAudioService().warmRemoteMicForRecording(networkId, peer?.deviceName).then((ok) => {
      if (this.vm.activeCamera?.networkId !== networkId) {
        return;
      }
      this.vm.remoteMicStatusHint = ok ?
        '✓ 对端麦克风已就绪，开录将直接收录对端声音' :
        '⏳ 开录时将再次尝试配置对端麦克风…';
      this.vm.recordingUiTick++;
    }).catch((err: Error) => {
      DhDiag.warn('VM', `warmRemoteMicForRecording failed ${JSON.stringify(err)}`);
      if (this.vm.activeCamera?.networkId === networkId) {
        this.vm.remoteMicStatusHint = '⏳ 开录时将再次尝试配置对端麦克风…';
        this.vm.recordingUiTick++;
      }
    });
  }

  public async handleDeviceOffline(event: DeviceStateChangeEvent): Promise<void> {
    try {
      const offlineId = event.device.deviceId;
      const active = this.vm.activeCamera;
      const isActiveRemote = active !== null &&
        active.sourceType === CameraSourceType.DISTRIBUTED &&
        (active.deviceId === offlineId || active.cameraId === offlineId || active.dhId === offlineId ||
          active.networkId === offlineId);
      if (!isActiveRemote) {
        this.vm.cameras = await this.vm.bridgeGetCameraService().enumerateCameras(true);
        this.updateRemoteFlag();
        return;
      }
      if (this.vm.isRecordingActive()) {
        await this.vm.stopOrCancelRecording();
      }
      await this.vm.bridgeGetOrchestrator().recoverOnRemoteOffline(event.device.deviceName,
        this.vm.bridgeGetCameraService().isRecording());
      this.vm.fallbackHint = `${event.device.deviceName} 已离线，已回退本机镜头与声场`;
      this.vm.cameras = await this.vm.bridgeGetCameraService().enumerateCameras(true);
      this.updateRemoteFlag();
      this.vm.sessionSummary = this.vm.bridgeGetOrchestrator().getSessionSummary();
      await this.vm.bridgeClosePipOverlay();
    } catch (err) {
      DhDiag.logCatchWarn('VM', 'handleDeviceOffline', err);
      this.vm.fallbackHint = `${event.device.deviceName} 离线处理异常，请手动切回本机镜头`;
    }
  }
}
