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
import { AppConstants } from '../../common/constants/AppConstants';
import { AppContext } from '../../common/context/AppContext';
import { CreationSessionState, ScenePrepareResult } from '../../common/types/CreationSessionTypes';
import { resolveSceneConfig } from '../../common/types/ScenePresets';
import {
  CameraFrameRateOption,
  CameraResolutionOption,
  CameraSourceType,
  CameraTarget,
  StreamSwitchResult,
  StreamSwitchState,
  StreamSwitchType,
  StreamPipelineType,
  StudioMode
} from '../../common/types/CameraTypes';
import {
  SCENE_TEMPLATES,
  SceneTemplate,
  SceneTemplateId,
  SuperPowerInfo
} from '../../common/types/SuperPowerTypes';
import { CameraSessionService } from '../../service/camera/CameraSessionService';
import { PipSessionService } from '../../service/PipSessionService';
import { GallerySaveResult } from '../../service/MediaGalleryService';
import { CreationSessionOrchestrator } from '../../service/CreationSessionOrchestrator';
import { StreamSwitchController } from '../../service/StreamSwitchController';
import { SuperPowerService } from '../../service/SuperPowerService';
import { DeviceManagerService } from '../../service/DeviceManagerService';
import { AudioRouteService, EndRecordingRemoteMicOptions } from '../../service/AudioRouteService';
import { AudioSourceType } from '../../common/types/AudioTypes';
import { DistributedHardwareService } from '../../service/DistributedHardwareService';
import {
  DeviceStateChangeAction,
  DeviceStateChangeEvent,
  DeviceListSource,
  DeviceOnlineState,
  RemotePeerReleaseEvent,
  TrustDeviceInfo
} from '../../common/types/DeviceTypes';
import {
  RemoteConnectKind,
  RemoteGuideStep
} from '../../common/types/RemoteConnectionTypes';
import { RemoteConnectionGuideHelper } from '../../service/RemoteConnectionGuideHelper';
import { PeerSignalService } from '../../service/PeerSignalService';
import streamMetricsNative from 'libentry.so';
import { DhDiag } from '../../common/util/DhDiag';
import { CreationIntentExecutor } from '../../service/switch/CreationIntentExecutor';
import {
  CreationIntentResult,
  ModeChangeHost,
  PhotoCaptureHost,
  PreviewConnectHost,
  VideoRecordHost
} from '../../service/switch/CreationIntentKind';
import { StudioVmUtils } from './StudioVmUtils';
import { StudioRecordingSection } from './StudioRecordingVm';
import {
  StudioModeChangeHost,
  StudioPhotoCaptureHost,
  StudioPreviewConnectHost,
  StudioVideoRecordHost
} from './StudioIntentHosts';
import { StudioStreamSpecSection } from './StudioStreamSpecSection';
import { StudioConnectivitySection } from './StudioConnectivitySection';

const TAG = AppConstants.TAG;

@Observed
export class StudioViewModel {
  public cameras: CameraTarget[] = [];
  public activeCamera: CameraTarget | null = null;
  public switchState: StreamSwitchState = StreamSwitchState.IDLE;
  public switchMessage: string = '';
  public studioMode: StudioMode = StudioMode.PREVIEW;
  public isRecording: boolean = false;
  public recordingBusy: boolean = false;
  /** idle | recording | stopping — 点录即 recording 并计时，点停即 stopping 保存相册 */
  public recordingPhase: string = 'idle';
  /** 录像已进行秒数（UI 计时器） */
  public recordingElapsedSec: number = 0;
  /** 驱动 UI 重绘（与 formatRecordingClock 一并读取） */
  public recordingUiTick: number = 0;
  /** 创作台面板/弹层状态变更时递增，驱动 @Link 子树刷新 */
  public studioUiTick: number = 0;
  /** 分辨率/帧率选项变更时递增，强制重建 Select（@Link 不刷新 options） */
  public streamSpecUiTick: number = 0;
  public firstFrameMs: number = -1;
  public switchElapsedMs: number = -1;
  public hasSwitchedStream: boolean = false;
  /** 本会话已成功连过远端镜头 — 后续走快路径，跳过 8s 引导等待 */
  public remoteSessionEstablished: boolean = false;
  public superPowers: SuperPowerInfo[] = [];
  public superPowerActiveCount: number = 0;
  public sceneTemplates: SceneTemplate[] = SCENE_TEMPLATES;
  public selectedSceneId: string = SceneTemplateId.DUAL_VLOG_STD;
  public surfaceId: string = '';
  public distributedReady: boolean = false;
  public localOnlyHint: string = '';
  public sessionState: CreationSessionState = CreationSessionState.UNINITIALIZED;
  public sessionSummary: string = '';
  public fallbackHint: string = '';
  public mediaHint: string = '';
  /** 对端麦/声场配置结果 — 优先展示在创作台状态条 */
  public remoteMicStatusHint: string = '';
  public hasRemoteCamera: boolean = false;
  public hasBoundRemote: boolean = false;
  public isPreparingScene: boolean = false;
  /** 创作台底部上拉工具面板（机位/模式/场景等） */
  public studioToolsExpanded: boolean = false;
  public studioToolsAutoClosePending: boolean = false;
  /** 远端→本机切流时保持工具面板展开，便于看到状态与重试 */
  public keepStudioToolsOpen: boolean = false;
  public showRemoteGuide: boolean = false;
  public remoteGuideTitle: string = '';
  public remoteGuideSteps: RemoteGuideStep[] = [];
  public remoteGuideProgress: string = '';
  public isConnectingRemote: boolean = false;
  public remotePeerDeviceName: string = '';
  public remoteGuideFailed: boolean = false;
  /** 用户点「画中画」后为 true，主镜头仍由机位按钮切换 */
  public pipOverlayVisible: boolean = false;
  public pipCamera: CameraTarget | null = null;
  public pipPreviewActive: boolean = false;
  public pipPreviewHint: string = '';
  public pipRecordingActive: boolean = false;
  /** 当前主路预览/计划录像分辨率，如 1280x720 YUV420 */
  public streamResolutionLabel: string = '';
  /** 当前计划录像帧率，如 30 fps */
  public streamFrameRateLabel: string = '';
  public streamResolutionOptions: CameraResolutionOption[] = [];
  public streamFpsOptions: CameraFrameRateOption[] = [];
  public selectedResolutionIndex: number = 0;
  public selectedFpsIndex: number = 0;
  /** 帧率滑块 1–60（与 selectedFps 同步） */
  public selectedFpsValue: number = 30;
  /** 点录像后弹出规格确认层 */
  public showRecordingSetup: boolean = false;
  /** 用户已确认过录像规格；再次点录像直接开录，停止后不再弹设置层 */
  public recordingSetupBusy: boolean = false;
  public recordingSetupResIndex: number = 0;
  /** 相对 recordingSetupResIndex 对应分辨率下的 fps 列表下标 */
  public recordingSetupFpsPickIndex: number = 0;
  public recordingSetupHint: string = '';
  public zoomSupported: boolean = false;
  public zoomMinRatio: number = 1;
  public zoomMaxRatio: number = 1;
  public zoomRatio: number = 1;
  /** 焦段尺 UI 选中档（点击即更新，不等待 getZoomRatio 读回） */
  public selectedPreviewZoomStop: number = 1;
  public focusSupported: boolean = false;
  public tapFocusSupported: boolean = false;
  public focusModeLabel: string = '';
  public focusStatusHint: string = '点击画面对焦';
  /** 预览辅助线 */
  public previewGridEnabled: boolean = false;
  /** 点击对焦标识（预览区像素坐标，相对 mainPreviewArea） */
  public focusIndicatorVisible: boolean = false;
  public focusIndicatorX: number = 0;
  public focusIndicatorY: number = 0;
  public zoomDragging: boolean = false;
  public focusIndicatorTimer: number = -1;
  public sceneApplyGeneration: number = 0;
  public appBootstrapReady: boolean = false;
  public bootstrapPreviewTimer: number = -1;
  public bootstrapPreviewInFlight: boolean = false;
  public surfaceRebindInFlight: boolean = false;
  public appInBackground: boolean = false;
  public appResumingFromBackground: boolean = false;
  public postPreviewControlsTimer: number = -1;
  /** 冷启动首开预览：跳过自动返听，避免与相机预览争用音频设备导致卡死/闪退 */
  public suppressPreviewMonitorOnce: boolean = false;
  /** 设备中心「设为镜头」选中的对端 networkId */
  public preferredRemoteNetworkId: string = '';
  /** 解绑/释放对端后须走冷连接（DH 预热 + 引导），勿信 CF 残留 REMOTE 枚举 */
  public coldReconnectAfterPeerRelease: boolean = false;
  /** 机位按钮乐观选中态（切流完成前即时反馈） */
  public pendingLensSource: string = '';
  public pendingLensPosition: string = '';

  private readonly recordingSection: StudioRecordingSection = new StudioRecordingSection(this);
  private readonly streamSpecSection: StudioStreamSpecSection = new StudioStreamSpecSection(this);
  private readonly connectivitySection: StudioConnectivitySection = new StudioConnectivitySection(this);

  private readonly cameraControlsAppliedListener = (): void => {
    this.streamSpecSection.refreshCameraControlsUi();
    this.bumpStudioUi();
  };

  private cameraService: CameraSessionService = CameraSessionService.getInstance();
  private pipService: PipSessionService = PipSessionService.getInstance();
  private switchController: StreamSwitchController = StreamSwitchController.getInstance();
  private orchestrator: CreationSessionOrchestrator = CreationSessionOrchestrator.getInstance();
  private spService: SuperPowerService = SuperPowerService.getInstance();
  private dmService: DeviceManagerService = DeviceManagerService.getInstance();
  private audioService: AudioRouteService = AudioRouteService.getInstance();
  private dhService: DistributedHardwareService = DistributedHardwareService.getInstance();

  private stateListener = (state: StreamSwitchState, message?: string): void => {
    this.switchState = state;
    this.switchMessage = message ?? '';
    if ((state === StreamSwitchState.SWITCHING || state === StreamSwitchState.PREPARING) &&
      this.studioToolsExpanded && !this.keepStudioToolsOpen) {
      this.closeStudioTools();
      this.studioToolsAutoClosePending = false;
    }
    if (this.showRemoteGuide && message) {
      this.remoteGuideProgress = message;
    }
    this.refreshSuperPowers();
    this.bumpStudioUi();
  };

  private sessionListener = (state: CreationSessionState, message: string): void => {
    this.sessionState = state;
    this.sessionSummary = this.orchestrator.getSessionSummary();
    if (this.showRemoteGuide && message) {
      this.remoteGuideProgress = message;
    }
    if (state === CreationSessionState.ROUTING_AUDIO && message.length > 0) {
      this.remoteMicStatusHint = '';
      this.mediaHint = message;
      this.fallbackHint = '';
    }
    if (state === CreationSessionState.READY) {
      this.publishAudioRouteReadyHint();
      void this.audioService.restartPreviewMonitor();
      if (message.length > 0) {
        this.mediaHint = this.remoteMicStatusHint.length > 0 ? this.remoteMicStatusHint : message;
      }
      this.fallbackHint = '';
    }
    if (state === CreationSessionState.FAILED) {
      this.fallbackHint = message;
      this.remoteMicStatusHint = '';
    }
  };

  private deviceStateListener = async (event: DeviceStateChangeEvent): Promise<void> => {
    try {
      if (event.action === DeviceStateChangeAction.OFFLINE) {
        await this.connectivitySection.handleDeviceOffline(event);
        return;
      }
      if (event.action === DeviceStateChangeAction.ONLINE ||
        event.action === DeviceStateChangeAction.READY) {
        await this.connectivitySection.refreshCamerasAndHints();
      }
    } catch (err) {
      DhDiag.logCatchWarn('VM', 'deviceStateListener', err);
    }
  };

  private deviceListListener = async (_devices: TrustDeviceInfo[]): Promise<void> => {
    try {
      await this.connectivitySection.refreshCamerasAndHints();
    } catch (err) {
      DhDiag.logCatchWarn('VM', 'deviceListListener', err);
    }
  };

  private peerReleaseListener = (event: RemotePeerReleaseEvent): void => {
    void this.connectivitySection.onRemotePeerReleased(event.networkId, event.deviceId);
  };

  public recordingTimerId: number = -1;
  public recordingWallStartMs: number = 0;
  /** 用户已点停止/取消，禁止 startRecordingFlow 结束后再次进入录制态 */
  public recordingStopRequested: boolean = false;
  /** 每次开录/点停递增，防止「停完后异步开录成功」又把 UI 拉回录像中 */
  public recordingFlowId: number = 0;
  public recordingStartInFlight: Promise<CreationIntentResult> | null = null;
  public recordingRemoteMicTask: Promise<boolean> | null = null;

  private recordingStateListener = (recording: boolean, hint: string): void => {
    if (recording) {
      if (this.recordingStopRequested || this.recordingPhase !== 'recording') {
        return;
      }
      if (hint.length > 0) {
        this.mediaHint = hint;
        this.recordingUiTick++;
      }
      return;
    }
    if (hint.length > 0 && (this.recordingPhase === 'recording' || this.recordingPhase === 'stopping')) {
      this.mediaHint = hint;
      this.fallbackHint = hint.includes('相册') || hint.includes('已保存') ? '' : this.fallbackHint;
      this.recordingUiTick++;
    }
    if (this.recordingPhase === 'idle') {
      this.bumpStudioUi();
    }
  };

  private recordingProgressListener = (hint: string): void => {
    if (this.recordingPhase !== 'recording' && this.recordingPhase !== 'preparing') {
      return;
    }
    if (hint.length > 0) {
      this.mediaHint = hint;
      this.applyRemoteMicProgressHint(hint);
      this.recordingUiTick++;
    }
  };

  /** 对端麦配置进度/结果 — 同步到底部状态条 */
  private applyRemoteMicProgressHint(hint: string): void {
    if (hint.length === 0) {
      return;
    }
    if (hint.includes('配置对端麦克风') || hint.includes('拉起对端 Mic') ||
      hint.includes('后台配置') || hint.includes('先出画')) {
      this.remoteMicStatusHint = hint.includes('✓') ? hint : '⏳ 对端麦配置中，录像先出画面…';
      return;
    }
    if (hint.includes('对端麦已就绪') || hint.includes('配置完成')) {
      this.remoteMicStatusHint = '✓ 对端麦克风已配置完成，录像将收录对端声音';
      this.fallbackHint = '';
      this.mediaHint = this.remoteMicStatusHint;
      return;
    }
    if (hint.includes('无音轨') || hint.includes('未就绪')) {
      this.remoteMicStatusHint = '⚠ 对端麦未就绪，先录画面（无对端声音）';
      this.fallbackHint = '';
      this.mediaHint = this.remoteMicStatusHint;
    }
  }

  private publishAudioRouteReadyHint(): void {
    const input = this.audioService.getRouteConfig().inputDevice;
    const route = this.audioService.getRouteSummary();
    const routeErr = this.audioService.getLastRouteError();
    const monitor = this.audioService.isPreviewMonitorActive() ? ' · 预览返听' : '';
    if (input?.sourceType === AudioSourceType.DISTRIBUTED) {
      this.remoteMicStatusHint = routeErr.length > 0 ?
        `✓ 对端麦克风已配置 · ${route}${monitor}（${routeErr}）` :
        `✓ 对端麦克风已配置完成 · ${route}${monitor}`;
    } else if (routeErr.includes('降级') || routeErr.includes('本机')) {
      this.remoteMicStatusHint = `⚠ ${routeErr} · ${route}${monitor}`;
    } else {
      this.remoteMicStatusHint = `✓ 声场已就绪 · ${route}${monitor}`;
    }
  }

  public async init(context?: common.UIAbilityContext): Promise<void> {
    DhDiag.flowBegin('BOOT', 'studioInit', '');
    const ctx = context ?? AppContext.tryGet() ?? undefined;
    await this.dmService.init(ctx);
    DhDiag.flowStep('BOOT', 'studioInit', 'dm', `ready=${this.dmService.isReady() ? 1 : 0}`);
    await this.audioService.init(ctx);
    DhDiag.flowStep('BOOT', 'studioInit', 'audio', `ready=${this.audioService.isReady() ? 1 : 0}`);
    this.dmService.onDeviceStateChanged(this.deviceStateListener);
    this.dmService.onDeviceListChanged(this.deviceListListener);
    this.dmService.onPeerReleased(this.peerReleaseListener);
    this.cameraService.init(ctx);
    this.cameraService.onRecordingStateChanged(this.recordingStateListener);
    this.cameraService.onRecordingProgress(this.recordingProgressListener);
    this.cameraService.onCameraControlsApplied(this.cameraControlsAppliedListener);
    this.orchestrator.onStateChange(this.sessionListener);
    this.switchController.onStateChange(this.stateListener);
    this.cameras = await this.cameraService.enumerateLocalCameras();
    this.connectivitySection.updateRemoteFlag();
    this.refreshStreamSpecLabels();
    this.refreshSuperPowers();
    this.sceneTemplates = AppConstants.SHOW_SCENE_TEMPLATE_UI ? SCENE_TEMPLATES : [];
    this.showRecordingSetup = false;
    this.studioToolsExpanded = false;
    this.zoomRatio = 1;
    this.selectedPreviewZoomStop = 1;
    this.zoomDragging = false;
    this.bumpStudioUi();
    DhDiag.flowEnd('BOOT', 'studioInit', true,
      `cameras=${this.cameras.length} boundRemote=${this.hasBoundRemote ? 1 : 0}`);
  }

  /** 从设备中心返回创作台时刷新绑定/相机状态 */
  public async refreshFromDeviceCenter(): Promise<void> {
    DhDiag.flowBegin('VM', 'refreshFromDeviceCenter', '');
    await this.dmService.refreshTrustDevices();
    await this.connectivitySection.refreshCamerasAndHints();
    this.connectivitySection.syncActiveCameraFromService();
    if (this.activeCamera === null && this.surfaceId.length > 0) {
      void this.scheduleBootstrapPreview();
    }
    this.bumpStudioUi();
    DhDiag.flowEnd('VM', 'refreshFromDeviceCenter', true,
      `cameras=${this.cameras.length} active=${this.activeCamera?.cameraId ?? 'none'}`);
  }

  /** 创作台 Page 注册的 UI 同步（@State 面板开关，弥补 @Observed+@Link 不刷新） */
  private studioPageUiSync: (() => void) | null = null;

  public registerStudioPageUiSync(sync: () => void): void {
    this.studioPageUiSync = sync;
  }

  public unregisterStudioPageUiSync(): void {
    this.studioPageUiSync = null;
  }

  public bumpStudioUi(): void {
    this.studioUiTick++;
    if (this.studioPageUiSync !== null) {
      this.studioPageUiSync();
    }
  }

  public setPendingLens(source: 'local' | 'remote', position: string): void {
    this.pendingLensSource = source;
    this.pendingLensPosition = position;
    this.bumpStudioUi();
  }

  public clearPendingLens(): void {
    if (this.pendingLensSource.length === 0 && this.pendingLensPosition.length === 0) {
      return;
    }
    this.pendingLensSource = '';
    this.pendingLensPosition = '';
    this.bumpStudioUi();
  }

  public getEffectiveLensPosition(): string {
    if (this.pendingLensPosition.length > 0) {
      return this.pendingLensPosition;
    }
    return this.activeCamera?.position ?? 'back';
  }

  public isEffectiveLensRemoteActive(): boolean {
    if (this.pendingLensSource === 'remote') {
      return true;
    }
    if (this.pendingLensSource === 'local') {
      return false;
    }
    return this.activeCamera?.sourceType === CameraSourceType.DISTRIBUTED;
  }

  public isEffectiveLensLocalActive(): boolean {
    return !this.isEffectiveLensRemoteActive();
  }

  /** Index 完成 DM + Studio 初始化后调用，再延迟开预览，避免与 Audio 分布式枚举并发 */
  public markAppBootstrapReady(): void {
    this.connectivitySection.markAppBootstrapReady();
  }

  public setSurfaceId(id: string): void {
    this.connectivitySection.setSurfaceId(id);
  }

  public static bridgeDelay(ms: number): Promise<void> {
    return StudioVmUtils.bridgeDelay(ms);
  }

  public buildPreviewConnectHost(): PreviewConnectHost {
    return new StudioPreviewConnectHost(this);
  }

  public buildVideoRecordHost(): VideoRecordHost {
    return new StudioVideoRecordHost(this);
  }

  public async changeMode(mode: StudioMode): Promise<void> {
    await CreationIntentExecutor.runModeChange(this.buildModeChangeHost(), mode);
  }

  private buildModeChangeHost(): ModeChangeHost {
    return new StudioModeChangeHost(this);
  }

  private buildPhotoCaptureHost(): PhotoCaptureHost {
    return new StudioPhotoCaptureHost(this);
  }

  public bridgeGetPipService(): PipSessionService {
    return this.pipService;
  }

  public async takePhoto(): Promise<void> {
    await CreationIntentExecutor.runPhotoCapture(this.buildPhotoCaptureHost());
  }

  public async toggleRecording(): Promise<void> {
    return this.recordingSection.toggleRecording();
  }

  public openRecordingSetup(): void {
    this.recordingSection.openRecordingSetup();
  }

  public dismissRecordingSetup(): void {
    this.recordingSection.dismissRecordingSetup();
  }

  public selectRecordingSetupResolution(index: number): void {
    this.recordingSection.selectRecordingSetupResolution(index);
  }

  public selectRecordingSetupFpsPick(index: number): void {
    this.recordingSection.selectRecordingSetupFpsPick(index);
  }

  public getRecordingSetupTargetFps(): number {
    return this.recordingSection.getRecordingSetupTargetFps();
  }

  public recordingSetupSubtitle(): string {
    return this.recordingSection.recordingSetupSubtitle();
  }

  public recordingSetupSummary(): string {
    return this.recordingSection.recordingSetupSummary();
  }

  public getRecordingSetupResolutionOptions(): SelectOption[] {
    return this.recordingSection.getRecordingSetupResolutionOptions();
  }

  public getRecordingSetupFpsOptions(): SelectOption[] {
    return this.recordingSection.getRecordingSetupFpsOptions();
  }

  public recordingSetupResolutionValue(): string {
    return this.recordingSection.recordingSetupResolutionValue();
  }

  public recordingSetupFpsValue(): string {
    return this.recordingSection.recordingSetupFpsValue();
  }

  public async confirmRecordingSetup(): Promise<void> {
    return this.recordingSection.confirmRecordingSetup();
  }

  public isRecordingActive(): boolean {
    return this.recordingSection.isRecordingActive();
  }

  public isRecordingClockVisible(): boolean {
    return this.recordingSection.isRecordingClockVisible();
  }

  public isRecordingPreparing(): boolean {
    return this.recordingPhase === 'preparing';
  }

  public isMainCameraRecording(): boolean {
    return this.recordingSection.isMainCameraRecording();
  }

  public formatRecordingClock(_uiTick: number = 0): string {
    return this.recordingSection.formatRecordingClock(_uiTick);
  }

  public resetRecordingUiAfterFailure(prevMode: StudioMode): void {
    this.recordingSection.resetRecordingUiAfterFailure(prevMode);
  }

  public startRecordingClock(resetWallStart: boolean = true): void {
    this.recordingSection.startRecordingClock(resetWallStart);
  }

  public stopRecordingClock(): void {
    this.recordingSection.stopRecordingClock();
  }

  public async startPipRecordingAsync(recordStamp: number): Promise<void> {
    return this.recordingSection.startPipRecordingAsync(recordStamp);
  }

  public async stopOrCancelRecording(): Promise<void> {
    return this.recordingSection.stopOrCancelRecording();
  }


  public async refreshCamerasAndHints(): Promise<void> {
    return this.connectivitySection.refreshCamerasAndHints();
  }

  public updateRemoteFlag(): void {
    this.connectivitySection.updateRemoteFlag();
  }

  public async scheduleBootstrapPreview(): Promise<void> {
    return this.connectivitySection.scheduleBootstrapPreview();
  }

  public onAppForeground(): void {
    this.connectivitySection.onAppForeground();
  }

  public onAppBackground(): void {
    this.connectivitySection.onAppBackground();
  }

  public resumePreviewAfterSurfaceChange(): Promise<void> {
    return this.connectivitySection.resumePreviewAfterSurfaceChange();
  }

  public setPipSurfaceId(id: string): void {
    this.connectivitySection.setPipSurfaceId(id);
  }

  public async togglePipOverlay(): Promise<void> {
    return this.connectivitySection.togglePipOverlay();
  }

  public async closePipOverlay(): Promise<void> {
    return this.connectivitySection.closePipOverlay();
  }

  public bridgeRefreshPipIfOpen(): Promise<void> {
    return this.connectivitySection.refreshPipIfOpen();
  }

  public bridgeClosePipOverlay(): Promise<void> {
    return this.connectivitySection.closePipOverlay();
  }

  public async selectCamera(target: CameraTarget, type: StreamSwitchType): Promise<void> {
    return this.connectivitySection.selectCamera(target, type);
  }

  public async switchToRemote(position: string = 'back'): Promise<void> {
    return this.connectivitySection.switchToRemote(position);
  }

  public async connectRemoteCamera(position: string = 'back'): Promise<void> {
    return this.connectivitySection.connectRemoteCamera(position);
  }

  public async retryConnectRemoteCamera(position: string = 'back'): Promise<void> {
    return this.connectivitySection.retryConnectRemoteCamera(position);
  }

  public dismissRemoteGuide(): void {
    this.connectivitySection.dismissRemoteGuide();
  }

  public getPrimaryBoundPeer(): TrustDeviceInfo | null {
    return this.connectivitySection.getPrimaryBoundPeer();
  }

  public async setLensFromDeviceCenter(networkId: string, position: string = 'back'): Promise<void> {
    return this.connectivitySection.setLensFromDeviceCenter(networkId, position);
  }

  public getPeerStandbyMessage(): string {
    return this.connectivitySection.getPeerStandbyMessage();
  }

  public async switchToRemoteDevice(networkId: string, position: string = 'back'): Promise<void> {
    return this.connectivitySection.switchToRemoteDevice(networkId, position);
  }

  public async connectOrSwitchRemote(position: string): Promise<void> {
    return this.connectivitySection.connectOrSwitchRemote(position);
  }

  public async connectOrSwitchLocal(position: string): Promise<void> {
    return this.connectivitySection.connectOrSwitchLocal(position);
  }

  public async switchLens(position: string): Promise<void> {
    return this.connectivitySection.switchLens(position);
  }

  public openStudioTools(): void {
    this.connectivitySection.openStudioTools();
  }

  public closeStudioTools(): void {
    this.connectivitySection.closeStudioTools();
  }

  public toggleStudioTools(): void {
    this.connectivitySection.toggleStudioTools();
  }

  /** 未选机位时引导用户展开工具面板选镜头（保持展开，避免切流后立刻被关掉） */
  public promptLensSelection(): void {
    this.keepStudioToolsOpen = true;
    this.studioToolsAutoClosePending = false;
    this.openStudioTools();
    this.mediaHint = '请在工具面板选择本机或远端镜头';
    this.fallbackHint = '';
    this.bumpStudioUi();
    DhDiag.info('VM', 'promptLensSelection — open studio tools');
  }

  public activeLensShortLabel(): string {
    return this.connectivitySection.activeLensShortLabel();
  }

  public async applySceneTemplate(template: SceneTemplate): Promise<void> {
    return this.connectivitySection.applySceneTemplate(template);
  }

  public async switchToLocal(): Promise<void> {
    return this.connectivitySection.switchToLocal();
  }

  public async onRemotePeerReleased(networkId: string, deviceId: string): Promise<void> {
    return this.connectivitySection.onRemotePeerReleased(networkId, deviceId);
  }

  public async handleDeviceOffline(event: DeviceStateChangeEvent): Promise<void> {
    return this.connectivitySection.handleDeviceOffline(event);
  }

  public syncActiveCameraFromService(): void {
    this.connectivitySection.syncActiveCameraFromService();
  }

  public refreshStreamSpecLabels(): void {
    this.streamSpecSection.refreshStreamSpecLabels();
  }

  public refreshStreamSpecLabelsForRecordingSetup(): void {
    this.streamSpecSection.refreshStreamSpecLabelsForRecordingSetup();
  }

  public async selectStreamResolutionAt(index: number): Promise<void> {
    return this.streamSpecSection.selectStreamResolutionAt(index);
  }

  public async selectStreamFrameRateAt(index: number): Promise<void> {
    return this.streamSpecSection.selectStreamFrameRateAt(index);
  }

  public async selectStreamFrameRateFps(fps: number): Promise<void> {
    return this.streamSpecSection.selectStreamFrameRateFps(fps);
  }

  public async setPreviewZoomRatio(ratio: number, smooth: boolean = false): Promise<void> {
    return this.streamSpecSection.setPreviewZoomRatio(ratio, smooth);
  }

  public dragPreviewZoomRatio(ratio: number): void {
    this.streamSpecSection.dragPreviewZoomRatio(ratio);
  }

  public getPreviewZoomUiMin(): number {
    return this.streamSpecSection.getPreviewZoomUiMin();
  }

  public getPreviewZoomUiMax(): number {
    return this.streamSpecSection.getPreviewZoomUiMax();
  }

  public clampPreviewZoomRatio(ratio: number): number {
    return this.streamSpecSection.clampPreviewZoomRatio(ratio);
  }

  public formatZoomStopLabel(ratio: number): string {
    return this.streamSpecSection.formatZoomStopLabel(ratio);
  }

  public formatPreviewZoomLabel(): string {
    return this.streamSpecSection.formatPreviewZoomLabel();
  }

  public togglePreviewGrid(): void {
    this.streamSpecSection.togglePreviewGrid();
  }

  public getPreviewZoomStops(): number[] {
    return this.streamSpecSection.getPreviewZoomStops();
  }

  public isPreviewZoomStopActive(stop: number): boolean {
    return this.streamSpecSection.isPreviewZoomStopActive(stop);
  }

  public selectPreviewZoomStop(stop: number): void {
    this.streamSpecSection.selectPreviewZoomStop(stop);
  }

  public async onPreviewTapFocus(localX: number, localY: number, areaW: number, areaH: number): Promise<void> {
    return this.streamSpecSection.onPreviewTapFocus(localX, localY, areaW, areaH);
  }

  public isStreamFpsSupported(fps: number): boolean {
    return this.streamSpecSection.isStreamFpsSupported(fps);
  }

  public resolutionFpsSummary(index: number): string {
    return this.streamSpecSection.resolutionFpsSummary(index);
  }

  public currentResolutionSupportedFps(): number[] {
    return this.streamSpecSection.currentResolutionSupportedFps();
  }

  public canChangeStreamSpec(): boolean {
    return this.streamSpecSection.canChangeStreamSpec();
  }

  public isRemoteMainCamera(): boolean {
    return this.streamSpecSection.isRemoteMainCamera();
  }

  public remoteStreamSpecHint(): string {
    return this.streamSpecSection.remoteStreamSpecHint();
  }

  public canChangeStreamFrameRate(): boolean {
    return this.streamSpecSection.canChangeStreamFrameRate();
  }

  public isStreamSpecChanging(): boolean {
    return this.streamSpecSection.isStreamSpecChanging();
  }

  public getResolutionSelectOptions(): SelectOption[] {
    return this.streamSpecSection.getResolutionSelectOptions();
  }

  public getFpsSelectOptions(): SelectOption[] {
    return this.streamSpecSection.getFpsSelectOptions();
  }

  public currentResolutionSelectValue(): string {
    return this.streamSpecSection.currentResolutionSelectValue();
  }

  public currentFpsSelectValue(): string {
    return this.streamSpecSection.currentFpsSelectValue();
  }

  public async cycleStreamResolution(): Promise<void> {
    return this.streamSpecSection.cycleStreamResolution();
  }

  public async cycleStreamFrameRate(): Promise<void> {
    return this.streamSpecSection.cycleStreamFrameRate();
  }

  public refreshMetrics(): void {
    const metrics = streamMetricsNative.getMetrics();
    this.firstFrameMs = metrics.firstFrameMs;
    this.switchElapsedMs = metrics.switchEndMs - metrics.switchStartMs;
  }

  public refreshSuperPowers(): void {
    this.superPowers = this.spService.computePowers({
      trustDevices: this.dmService.getTrustDevices(),
      hasSwitchedStream: this.hasSwitchedStream,
      offlineFallbackEnabled: true,
      switchState: this.switchState,
      previewActive: this.activeCamera !== null
    });
    this.superPowerActiveCount = this.spService.getActiveCount(this.superPowers);
  }

  /** 创作台底部单行状态（优先告警，其次媒体提示） */
  public statusLine(): string {
    if (this.fallbackHint.length > 0) {
      return this.fallbackHint;
    }
    if (this.remoteMicStatusHint.length > 0) {
      return this.remoteMicStatusHint;
    }
    if (this.mediaHint.length > 0) {
      return this.mediaHint;
    }
    if (this.localOnlyHint.length > 0) {
      return this.localOnlyHint;
    }
    if (this.isConnectingRemote && this.switchMessage.length > 0) {
      return this.switchMessage;
    }
    if (this.isPreparingScene) {
      return '正在连接对端手机并配置声场…';
    }
    if (this.focusStatusHint.length > 0) {
      return this.focusStatusHint;
    }
    return '';
  }


  /** Creation command host adapters — bridge private VM state/services */
  public bridgeGetCameraService(): CameraSessionService {
    return this.cameraService;
  }

  public bridgeGetDmService(): DeviceManagerService {
    return this.dmService;
  }

  public bridgeGetDhService(): DistributedHardwareService {
    return this.dhService;
  }

  public bridgeGetSwitchController(): StreamSwitchController {
    return this.switchController;
  }

  public bridgeGetOrchestrator(): CreationSessionOrchestrator {
    return this.orchestrator;
  }

  public bridgeGetAudioService(): AudioRouteService {
    return this.audioService;
  }

  public bridgeApplySwitchResult(result: StreamSwitchResult): Promise<void> {
    return this.connectivitySection.applySwitchResult(result);
  }

  public bridgeUpdateRemoteFlag(): void {
    this.updateRemoteFlag();
  }

  public bridgeSyncActiveCameraFromService(): void {
    this.syncActiveCameraFromService();
  }

  public bridgeRefreshStreamSpecLabels(): void {
    this.refreshStreamSpecLabels();
    this.bumpStudioUi();
  }

  public bridgeRefreshStreamSpecLabelsForRecordingSetup(): void {
    this.refreshStreamSpecLabelsForRecordingSetup();
    this.bumpStudioUi();
  }

  public bridgeEnsureRecordingSetupOptions(): Promise<boolean> {
    if (this.cameraService.ensureRecordingSetupOptionsSync()) {
      return Promise.resolve(true);
    }
    return this.cameraService.ensureRecordingSetupOptionsAsync();
  }

  public bridgePublishAudioRouteReadyHint(): void {
    this.publishAudioRouteReadyHint();
  }

  public bridgeResetRecordingUiAfterFailure(prevMode: StudioMode): void {
    this.resetRecordingUiAfterFailure(prevMode);
  }

  public bridgeStartPipRecordingAsync(recordStamp: number): Promise<void> {
    return this.startPipRecordingAsync(recordStamp);
  }

  public bridgeStartRecordingClock(resetWallStart: boolean): void {
    this.startRecordingClock(resetWallStart);
  }

  public bridgeIsRemoteSessionEstablished(): boolean {
    return this.remoteSessionEstablished;
  }

  public bridgeSetRemoteSessionEstablished(established: boolean): void {
    this.remoteSessionEstablished = established;
  }

  public bridgeAllocateRecordingFlowId(): number {
    this.recordingStopRequested = false;
    return ++this.recordingFlowId;
  }

  public bridgeGetRecordingFlowId(): number {
    return this.recordingFlowId;
  }

  public bridgeIsRecordingStopRequested(): boolean {
    return this.recordingStopRequested;
  }

  public bridgeSetRecordingStartInFlight(task: Promise<CreationIntentResult> | null): void {
    this.recordingStartInFlight = task;
  }

  public bridgeGetRecordingStartInFlight(): Promise<CreationIntentResult> | null {
    return this.recordingStartInFlight;
  }

  public bridgeSetRecordingRemoteMicTask(task: Promise<boolean> | null): void {
    this.recordingRemoteMicTask = task;
  }

  public bridgeShouldAbortRecording(flowId: number): boolean {
    return this.recordingFlowId !== flowId || this.recordingStopRequested;
  }

  public release(): void {
    if (this.bootstrapPreviewTimer >= 0) {
      clearTimeout(this.bootstrapPreviewTimer);
      this.bootstrapPreviewTimer = -1;
    }
    if (this.postPreviewControlsTimer >= 0) {
      clearTimeout(this.postPreviewControlsTimer);
      this.postPreviewControlsTimer = -1;
    }
    if (this.focusIndicatorTimer >= 0) {
      clearTimeout(this.focusIndicatorTimer);
      this.focusIndicatorTimer = -1;
    }
    this.stopRecordingClock();
    void this.audioService.stopPreviewMonitor();
    this.cameraService.offRecordingStateChanged(this.recordingStateListener);
    this.cameraService.offRecordingProgress(this.recordingProgressListener);
    this.dmService.offDeviceListChanged(this.deviceListListener);
    this.dmService.offDeviceStateChanged(this.deviceStateListener);
    this.dmService.offPeerReleased(this.peerReleaseListener);
    this.switchController.offStateChange(this.stateListener);
    this.orchestrator.offStateChange(this.sessionListener);
    this.pipOverlayVisible = false;
    this.studioToolsExpanded = false;
    this.showRecordingSetup = false;
    this.keepStudioToolsOpen = false;
    this.studioToolsAutoClosePending = false;
    void this.pipService.close();
    this.cameraService.closeSession();
    this.bumpStudioUi();
  }
}
