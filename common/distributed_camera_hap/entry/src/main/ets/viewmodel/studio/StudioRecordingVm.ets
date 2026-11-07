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

import { AppConstants } from '../../common/constants/AppConstants';
import { resolveSceneConfig } from '../../common/types/ScenePresets';
import { CameraSourceType, CameraTarget, StudioMode } from '../../common/types/CameraTypes';
import { SceneTemplateId } from '../../common/types/SuperPowerTypes';
import { GallerySaveResult } from '../../service/MediaGalleryService';
import { EndRecordingRemoteMicOptions } from '../../service/AudioRouteService';
import { CreationIntentExecutor } from '../../service/switch/CreationIntentExecutor';
import { DhDiag } from '../../common/util/DhDiag';
import { StudioViewModel } from './StudioViewModel';
import { StudioVmUtils } from './StudioVmUtils';

export class StudioRecordingSection {
  private readonly vm: StudioViewModel;

  constructor(vm: StudioViewModel) {
    this.vm = vm;
  }

  public async toggleRecording(): Promise<void> {
    if (this.isStaleRecordingUi()) {
      DhDiag.warn('VM', 'toggleRecording — reset stale preparing UI');
      this.resetRecordingUiAfterFailure(this.vm.studioMode);
      this.vm.recordingBusy = false;
      this.vm.recordingStartInFlight = null;
      this.vm.bumpStudioUi();
    }
    if (this.isRecordingActive() || this.vm.recordingBusy || this.vm.recordingStartInFlight !== null) {
      DhDiag.flowBegin('VM', 'stopRecording', '');
      await this.stopOrCancelRecording();
      DhDiag.flowEnd('VM', 'stopRecording', true, '');
      return;
    }
    if (this.vm.showRecordingSetup) {
      DhDiag.info('VM', 'toggleRecording — setup open, use overlay 开始录像/取消');
      return;
    }
    await this.ensureCameraBeforeRecording();
    this.vm.bridgeSyncActiveCameraFromService();
    if (this.vm.activeCamera === null) {
      this.vm.promptLensSelection();
      DhDiag.info('VM', 'toggleRecording — no activeCamera, opened lens tools');
      return;
    }
    this.openRecordingSetup();
  }

  /** 未选机位时先尝试 bootstrap，避免点录像无反应 */
  private async ensureCameraBeforeRecording(): Promise<void> {
    this.vm.bridgeSyncActiveCameraFromService();
    if (this.vm.activeCamera !== null) {
      return;
    }
    if (this.vm.surfaceId.length === 0) {
      DhDiag.warn('VM', 'ensureCameraBeforeRecording — preview target not ready');
      return;
    }
    this.vm.mediaHint = '正在就绪镜头…';
    this.vm.bumpStudioUi();
    if (!this.vm.bridgeGetCameraService().isActive()) {
      DhDiag.info('VM', 'ensureCameraBeforeRecording — scheduleBootstrapPreview');
      await this.vm.scheduleBootstrapPreview();
    }
    this.vm.bridgeSyncActiveCameraFromService();
    const current: CameraTarget | null = this.vm.bridgeGetCameraService().getCurrentTarget();
    if (this.vm.activeCamera === null && current !== null) {
      this.vm.activeCamera = current;
    }
    const activeId: string = current !== null ? current.cameraId : 'none';
    this.vm.bumpStudioUi();
    DhDiag.info('VM',
      `ensureCameraBeforeRecording done active=${activeId} vm=${this.vm.activeCamera?.cameraId ?? 'none'} ` +
      `cfActive=${this.vm.bridgeGetCameraService().isActive() ? 1 : 0}`);
  }

  /** 开录失败或中断后 UI 仍停在 preparing — 避免底栏一直当「录像中」点不动 */
  private isStaleRecordingUi(): boolean {
    return (this.vm.recordingPhase === 'preparing' || this.vm.isRecording) &&
      this.vm.recordingStartInFlight === null &&
      !this.vm.recordingBusy &&
      !this.vm.bridgeGetCameraService().isRecording() &&
      !this.vm.bridgeGetCameraService().hasRecordingSession();
  }

  public openRecordingSetup(): void {
    if (this.vm.recordingBusy || this.vm.recordingStartInFlight !== null) {
      DhDiag.warn('VM', 'openRecordingSetup skip — recording busy');
      return;
    }
    this.vm.closeStudioTools();
    this.vm.recordingSetupBusy = false;
    this.vm.recordingSetupHint = '';
    this.vm.recordingSetupResIndex = Math.max(0, this.vm.selectedResolutionIndex);
    if (this.vm.streamResolutionOptions.length > 0) {
      this.syncRecordingSetupFpsPickFromCurrent();
    }
    this.vm.showRecordingSetup = true;
    this.vm.mediaHint = '请选择录像分辨率与帧率，点「开始录像」';
    this.vm.fallbackHint = '';
    this.vm.recordingUiTick++;
    this.vm.bumpStudioUi();
    DhDiag.info('VM',
      `openRecordingSetup instant remote=${this.vm.isRemoteMainCamera() ? 1 : 0} ` +
      `resOpts=${this.vm.streamResolutionOptions.length}`);
    void this.finishOpenRecordingSetup();
  }

  /** 弹层已显示后再补全/刷新规格（避免点击录像时同步 refresh 拖慢首帧） */
  private async finishOpenRecordingSetup(): Promise<void> {
    const t0 = Date.now();
    this.vm.recordingSetupBusy = true;
    try {
      this.vm.bridgeRefreshStreamSpecLabelsForRecordingSetup();
      if (this.vm.streamResolutionOptions.length === 0) {
        this.vm.recordingSetupHint = '正在加载可用规格…';
        this.vm.recordingUiTick++;
      }
      let ok = this.vm.streamResolutionOptions.length > 0;
      if (!ok) {
        ok = await this.vm.bridgeEnsureRecordingSetupOptions();
        this.vm.bridgeRefreshStreamSpecLabelsForRecordingSetup();
      }
      if (!ok || this.vm.streamResolutionOptions.length === 0) {
        this.vm.showRecordingSetup = true;
        this.vm.recordingSetupHint = '规格加载失败，请换机位或稍后重试';
        this.vm.fallbackHint = '当前镜头尚未就绪，请稍候再试';
        DhDiag.warn('VM', `finishOpenRecordingSetup failed elapsed=${Date.now() - t0}ms`);
        return;
      }
      this.vm.recordingSetupResIndex = Math.min(this.vm.selectedResolutionIndex,
        this.vm.streamResolutionOptions.length - 1);
      this.syncRecordingSetupFpsPickFromCurrent();
      this.vm.recordingSetupHint = '';
      DhDiag.info('VM',
        `finishOpenRecordingSetup ok res[${this.vm.recordingSetupResIndex}] ` +
        `fpsPick=${this.vm.recordingSetupFpsPickIndex} elapsed=${Date.now() - t0}ms`);
    } catch (err) {
      DhDiag.logCatchWarn('VM', 'finishOpenRecordingSetup', err);
      this.vm.recordingSetupHint = '规格加载异常，请稍后重试';
      this.vm.fallbackHint = '录像规格加载失败';
    } finally {
      this.vm.recordingSetupBusy = false;
      this.vm.recordingUiTick++;
      this.vm.bumpStudioUi();
    }
  }

  public dismissRecordingSetup(): void {
    if (this.vm.recordingSetupBusy) {
      DhDiag.warn('VM', 'dismissRecordingSetup — abort busy spec apply');
      this.vm.bridgeGetCameraService().resetSpecChangeGate();
      this.vm.recordingSetupBusy = false;
      this.vm.recordingSetupHint = '';
      const cam = this.vm.activeCamera;
      if (cam && !this.vm.bridgeGetCameraService().isActive()) {
        void this.vm.bridgeGetCameraService().openAndPreview(cam, StudioMode.PREVIEW,
          this.vm.bridgeGetCameraService().getCurrentPipeline(), false);
      }
    }
    this.vm.showRecordingSetup = false;
    this.vm.recordingSetupHint = '';
    this.vm.bumpStudioUi();
    DhDiag.info('VM', 'dismissRecordingSetup');
  }

  public selectRecordingSetupResolution(index: number): void {
    if (index < 0 || index >= this.vm.streamResolutionOptions.length) {
      return;
    }
    const prevFps = this.getRecordingSetupTargetFps();
    this.vm.recordingSetupResIndex = index;
    const fpsList: number[] = this.vm.bridgeGetCameraService().getSupportedFpsForResolutionIndex(index);
    if (fpsList.length === 0) {
      this.vm.recordingSetupFpsPickIndex = 0;
      return;
    }
    let pick = fpsList.indexOf(prevFps);
    if (pick < 0) {
      pick = fpsList.indexOf(this.vm.selectedFpsValue);
    }
    if (pick < 0) {
      pick = 0;
    }
    this.vm.recordingSetupFpsPickIndex = pick;
  }

  public selectRecordingSetupFpsPick(index: number): void {
    const fpsList: number[] = this.vm.bridgeGetCameraService()
      .getSupportedFpsForResolutionIndex(this.vm.recordingSetupResIndex);
    if (index < 0 || index >= fpsList.length) {
      return;
    }
    this.vm.recordingSetupFpsPickIndex = index;
  }

  public getRecordingSetupTargetFps(): number {
    const fpsList: number[] = this.vm.bridgeGetCameraService()
      .getSupportedFpsForResolutionIndex(this.vm.recordingSetupResIndex);
    if (fpsList.length === 0) {
      return 30;
    }
    const idx = Math.min(this.vm.recordingSetupFpsPickIndex, fpsList.length - 1);
    return fpsList[idx];
  }

  public recordingSetupSubtitle(): string {
    if (!this.vm.activeCamera) {
      return '请选择机位后开始录像';
    }
    const cam = this.vm.activeCamera;
    const src = cam.sourceType === CameraSourceType.LOCAL ? '本机' : cam.deviceName;
    const lens = cam.position === 'front' ? '前摄' : '后摄';
    return `${src} · ${lens} · 确认后将按所选规格开录并计时`;
  }

  public recordingSetupSummary(): string {
    const res = this.vm.streamResolutionOptions[this.vm.recordingSetupResIndex];
    const label = res !== undefined ? res.label : '—';
    return `将录制 ${label} · ${this.getRecordingSetupTargetFps()} fps`;
  }

  public getRecordingSetupResolutionOptions(): SelectOption[] {
    const result: SelectOption[] = [];
    for (let i = 0; i < this.vm.streamResolutionOptions.length; i++) {
      result.push({ value: this.vm.streamResolutionOptions[i].label });
    }
    if (result.length === 0) {
      result.push({ value: '无可用分辨率' });
    }
    return result;
  }

  public getRecordingSetupFpsOptions(): SelectOption[] {
    const fpsList: number[] = this.vm.bridgeGetCameraService()
      .getSupportedFpsForResolutionIndex(this.vm.recordingSetupResIndex);
    if (fpsList.length === 0) {
      return [{ value: '无可用帧率' }];
    }
    const result: SelectOption[] = [];
    for (const fps of fpsList) {
      result.push({ value: `${fps} fps` });
    }
    return result;
  }

  public recordingSetupResolutionValue(): string {
    const opts = this.getRecordingSetupResolutionOptions();
    const idx = Math.min(this.vm.recordingSetupResIndex, opts.length - 1);
    return idx >= 0 ? opts[idx].value as string : '分辨率';
  }

  public recordingSetupFpsValue(): string {
    const opts = this.getRecordingSetupFpsOptions();
    const idx = Math.min(this.vm.recordingSetupFpsPickIndex, opts.length - 1);
    return idx >= 0 ? opts[idx].value as string : '帧率';
  }

  public syncRecordingSetupFpsPickFromCurrent(): void {
    const fpsList: number[] = this.vm.bridgeGetCameraService()
      .getSupportedFpsForResolutionIndex(this.vm.recordingSetupResIndex);
    if (fpsList.length === 0) {
      this.vm.recordingSetupFpsPickIndex = 0;
      return;
    }
    let pick = fpsList.indexOf(this.vm.selectedFpsValue);
    if (pick < 0 && this.vm.streamFpsOptions.length > 0) {
      pick = fpsList.indexOf(this.vm.streamFpsOptions[this.vm.selectedFpsIndex].fps);
    }
    if (pick < 0) {
      pick = 0;
    }
    this.vm.recordingSetupFpsPickIndex = pick;
  }

  public async confirmRecordingSetup(): Promise<void> {
    if (this.vm.recordingSetupBusy || !this.vm.activeCamera) {
      return;
    }
    this.vm.recordingSetupBusy = true;
    this.vm.showRecordingSetup = false;
    this.vm.recordingSetupHint = this.vm.isRemoteMainCamera() ?
      '已确认规格，即将启动远端录像…' : '正在启动录像…';
    this.vm.recordingPhase = 'preparing';
    this.vm.isRecording = true;
    this.vm.bridgeGetOrchestrator().markRecording(true);
    this.vm.mediaHint = this.vm.isRemoteMainCamera() ?
      '⏳ 正在准备远端录像，请稍候…' : '⏳ 正在准备录像，请稍候…';
    this.vm.recordingUiTick++;
    this.vm.bumpStudioUi();
    DhDiag.info('REC',
      `confirmRecordingSetup preparing remote=${this.vm.isRemoteMainCamera() ? 1 : 0} ` +
      `res[${this.vm.recordingSetupResIndex}] fpsPick=${this.vm.recordingSetupFpsPickIndex} clock=deferred`);
    await StudioVmUtils.bridgeDelay(32);
    try {
      const ok = await this.applyRecordingSetupSpec();
      if (!ok) {
        this.resetRecordingUiAfterFailure(this.vm.studioMode);
        this.vm.showRecordingSetup = true;
        this.vm.recordingSetupHint = this.vm.bridgeGetCameraService().getLastPhotoHint().length > 0 ?
          this.vm.bridgeGetCameraService().getLastPhotoHint() : '规格应用失败，请重试或更换选项';
        this.vm.bumpStudioUi();
        return;
      }
      this.vm.recordingSetupHint = '';
      await this.startRecordingFlow();
    } catch (err) {
      DhDiag.logCatchWarn('VM', 'confirmRecordingSetup', err);
      this.resetRecordingUiAfterFailure(this.vm.studioMode);
      this.vm.fallbackHint = '录像启动异常，请稍后重试';
    } finally {
      this.vm.recordingSetupBusy = false;
      this.vm.recordingUiTick++;
      this.vm.bumpStudioUi();
    }
  }

  /** 按录像设置弹层的选择 pin 规格；远端不重建预览，开录时 video.prepare 再 DH+Video */
  public async applyRecordingSetupSpec(): Promise<boolean> {
    const resIdx = this.vm.recordingSetupResIndex;
    const targetFps = this.getRecordingSetupTargetFps();
    if (resIdx < 0 || resIdx >= this.vm.streamResolutionOptions.length) {
      return false;
    }
    DhDiag.info('VM',
      `applyRecordingSetupSpec res[${resIdx}]=${this.vm.streamResolutionOptions[resIdx].label} fps=${targetFps} ` +
      `remote=${this.vm.isRemoteMainCamera() ? 1 : 0}`);

    if (this.vm.isRemoteMainCamera()) {
      const ok = this.vm.bridgeGetCameraService().applyDistributedRecordingStreamSpec(resIdx, targetFps);
      this.vm.bridgeRefreshStreamSpecLabels();
      return ok;
    }

    const fpsIdx = this.vm.streamFpsOptions.findIndex(o => o.fps === targetFps);
    const fpsPick = fpsIdx >= 0 ? fpsIdx : this.vm.selectedFpsIndex;
    this.vm.bridgeGetCameraService().stageUserStreamSpec(resIdx, fpsPick);
    this.vm.bridgeGetCameraService().commitUserStreamSpec('recordingSetup.confirm');
    this.vm.selectedResolutionIndex = resIdx;
    this.vm.selectedFpsIndex = fpsPick;
    if (fpsPick >= 0 && fpsPick < this.vm.streamFpsOptions.length) {
      this.vm.selectedFpsValue = this.vm.streamFpsOptions[fpsPick].fps;
    }
    this.vm.bridgeRefreshStreamSpecLabels();
    const cam = this.vm.activeCamera;
    if (cam) {
      this.vm.recordingSetupHint = '正在预热录像会话…';
      this.vm.bumpStudioUi();
      const warmT0 = Date.now();
      const warmed = await this.vm.bridgeGetCameraService().prepareVideoSessionForRecording(cam);
      DhDiag.info('VM',
        `applyRecordingSetupSpec local video.prepare warmed=${warmed ? 1 : 0} elapsed=${Date.now() - warmT0}ms`);
      if (!warmed) {
        return false;
      }
    }
    DhDiag.info('VM', `applyRecordingSetupSpec local ok res[${resIdx}] fps=${targetFps}`);
    return true;
  }

  /** 停止录像 — 落盘并弹窗保存相册（与本机一致） */
  public async stopOrCancelRecording(): Promise<void> {
    this.vm.recordingFlowId++;
    this.vm.recordingStopRequested = true;
    this.vm.recordingPhase = 'stopping';
    this.vm.isRecording = false;
    this.vm.recordingBusy = false;
    const recordUiMs = this.vm.recordingWallStartMs > 0 ? Date.now() - this.vm.recordingWallStartMs : 0;
    this.stopRecordingClock();
    this.vm.mediaHint = '正在保存到相册…';
    this.vm.recordingUiTick++;
    this.vm.bridgeGetAudioService().cancelRecordingRemoteMicSetup();
    const alreadyWriting = this.vm.bridgeGetCameraService().isRecording();
    if (!alreadyWriting && recordUiMs < 3000) {
      this.vm.bridgeGetCameraService().requestAbortRecordingStart();
    }

    try {
      let pipSaved: GallerySaveResult | null = null;
      if (this.vm.bridgeGetPipService().isPipRecording()) {
        pipSaved = await StudioVmUtils.awaitWithDeadline(
          this.vm.bridgeGetPipService().stopRecording(true), 8000, null);
        this.vm.pipRecordingActive = false;
      }
      const startTask = this.vm.recordingStartInFlight;
      this.vm.recordingStartInFlight = null;
      if (startTask !== null) {
        const startWaitMs = recordUiMs >= 3000 ? AppConstants.USER_STOP_WAIT_START_LONG_MS :
          (recordUiMs >= 1000 ? 12000 : AppConstants.USER_STOP_WAIT_START_MS);
        if (!alreadyWriting && recordUiMs >= 3000) {
          this.vm.mediaHint = '正在结束录像并落盘…';
          this.vm.recordingUiTick++;
        }
        await StudioVmUtils.awaitWithDeadline(startTask, startWaitMs, undefined);
      }
      if (!this.vm.bridgeGetCameraService().isRecording()) {
        this.vm.bridgeGetCameraService().requestAbortRecordingStart();
        this.vm.bridgeGetCameraService().forceEndRecordingPrepare();
      }
      const micTask = this.vm.recordingRemoteMicTask;
      this.vm.recordingRemoteMicTask = null;
      if (micTask !== null) {
        await StudioVmUtils.awaitWithDeadline(micTask, AppConstants.USER_STOP_WAIT_START_MS, false);
      }
      this.vm.mediaHint = '正在保存到相册…';
      this.vm.recordingUiTick++;
      DhDiag.info('FLOW',
        `stopOrCancel uiMs=${recordUiMs} camRec=${this.vm.bridgeGetCameraService().isRecording() ? 1 : 0} ` +
        `hasSession=${this.vm.bridgeGetCameraService().hasRecordingSession() ? 1 : 0}`);
      const ok = await StudioVmUtils.awaitWithDeadline(
        this.vm.bridgeGetCameraService().stopRecordingForUser(true),
        AppConstants.USER_STOP_RECORD_TOTAL_MS, false);
      if (this.vm.activeCamera?.sourceType === CameraSourceType.DISTRIBUTED ||
        this.vm.bridgeGetAudioService().isRecordingRemoteMicSession()) {
        this.vm.mediaHint = '正在关闭对端麦克风…';
        this.vm.recordingUiTick++;
        await StudioVmUtils.awaitWithDeadline(
          this.vm.bridgeGetAudioService().endRecordingRemoteMic(this.buildEndRecordingRestoreOptions()),
          AppConstants.USER_STOP_END_REMOTE_MIC_MS, undefined);
      }
      const hint = this.vm.bridgeGetCameraService().getLastPhotoHint();
      const segments = this.vm.bridgeGetCameraService().getRecordingSegments();
      const gallerySaved = ok || hint.includes('相册') || hint.includes('已保存');
      if (gallerySaved) {
        const parts: string[] = [];
        parts.push(hint.length > 0 ? hint :
          (segments.length > 0 ? '视频已保存到相册' : '录像已结束'));
        if (pipSaved) {
          parts.push(pipSaved.success ? `辅路：${pipSaved.message}` : `辅路保存失败：${pipSaved.message}`);
        }
        this.vm.mediaHint = parts.join(' · ');
        this.vm.fallbackHint = '';
      } else if (segments.length > 0) {
        this.vm.mediaHint = hint.length > 0 ? hint :
          '主路片段已在应用目录，相册保存未成功 · ' +
          '请在系统弹窗中点「允许/保存」后重试';
        this.vm.fallbackHint = this.vm.mediaHint;
      } else if (hint.includes('未生成') || hint.includes('无效') || hint.includes('为空')) {
        this.vm.mediaHint = hint;
        this.vm.fallbackHint = '';
      } else if (ok === false && hint.length === 0) {
        this.vm.mediaHint = '停止录像超时，请稍后在相册或应用目录查看是否已有片段';
        this.vm.fallbackHint = this.vm.mediaHint;
      } else {
        this.vm.mediaHint = hint.length > 0 ? hint : '停止录像未完成，请重试';
        this.vm.fallbackHint = this.vm.mediaHint;
      }
    } catch (err) {
      DhDiag.error('VM', `stopOrCancelRecording failed ${JSON.stringify(err)}`);
      this.vm.mediaHint = '停止录像异常，请重试';
      this.vm.fallbackHint = this.vm.mediaHint;
    } finally {
      this.stopRecordingClock();
      this.vm.isRecording = false;
      this.vm.recordingPhase = 'idle';
      this.vm.recordingBusy = false;
      this.vm.recordingStopRequested = false;
      this.vm.bridgeGetOrchestrator().markRecording(false);
      void this.vm.bridgeGetAudioService().lockRecordMicForAvRecorder(false);
      this.vm.bridgeGetAudioService().resumePreviewMonitor();
      void this.vm.bridgeGetAudioService().restartPreviewMonitor();
      this.vm.bridgePublishAudioRouteReadyHint();
      this.vm.recordingUiTick++;
      this.vm.bumpStudioUi();
    }
  }

  public buildEndRecordingRestoreOptions(): EndRecordingRemoteMicOptions {
    const sceneConfig = resolveSceneConfig(this.vm.selectedSceneId as SceneTemplateId);
    const opts: EndRecordingRemoteMicOptions = {
      restorePreset: sceneConfig.audioPreset
    };
    if (this.vm.activeCamera?.networkId) {
      opts.remoteNetworkId = this.vm.activeCamera.networkId;
    }
    return opts;
  }

  public async startRecordingFlow(): Promise<void> {
    const result = await CreationIntentExecutor.runVideoRecord(this.vm.buildVideoRecordHost());
    if (!result.success) {
      const msg = result.message.length > 0 ? result.message :
        this.vm.bridgeGetCameraService().getLastPhotoHint();
      if (msg.length > 0) {
        this.vm.fallbackHint = msg;
        this.vm.mediaHint = msg;
      }
      this.vm.bumpStudioUi();
    }
  }

  public resetRecordingUiAfterFailure(prevMode: StudioMode): void {
    this.vm.bridgeGetAudioService().cancelRecordingRemoteMicSetup();
    void this.vm.bridgeGetAudioService().endRecordingRemoteMic(this.buildEndRecordingRestoreOptions());
    this.vm.recordingRemoteMicTask = null;
    this.vm.recordingPhase = 'idle';
    this.vm.isRecording = false;
    this.stopRecordingClock();
    this.vm.studioMode = prevMode;
    this.vm.bridgeGetOrchestrator().markRecording(false);
    void this.vm.bridgeGetAudioService().lockRecordMicForAvRecorder(false);
    this.vm.bridgeGetAudioService().resumePreviewMonitor();
    void this.vm.bridgeGetAudioService().restartPreviewMonitor();
    this.vm.recordingUiTick++;
    this.vm.bumpStudioUi();
  }

  public async startPipRecordingAsync(recordStamp: number): Promise<void> {
    const pipRecordOk = await this.vm.bridgeGetPipService().startRecording(recordStamp);
    this.vm.pipRecordingActive = pipRecordOk;
    if (this.vm.recordingPhase !== 'recording') {
      return;
    }
    const base = this.vm.bridgeGetCameraService().getLastPhotoHint();
    let hint = base.length > 0 ? base : '录像中…';
    hint += pipRecordOk ? ' · 主+辅双文件' : ' · 仅主路（辅路录制未启动）';
    this.vm.mediaHint = hint;
  }

  public isRecordingActive(): boolean {
    if (this.vm.recordingPhase === 'preparing' ||
      this.vm.recordingPhase === 'recording' ||
      this.vm.recordingPhase === 'stopping') {
      return true;
    }
    return this.vm.recordingBusy &&
      (this.vm.recordingStartInFlight !== null ||
        this.vm.bridgeGetCameraService().isRecording() ||
        this.vm.bridgeGetCameraService().hasRecordingSession());
  }

  /** 仅正式写入后显示计时器（preparing 阶段不计时） */
  public isRecordingClockVisible(): boolean {
    return this.vm.recordingPhase === 'recording' || this.vm.recordingPhase === 'stopping';
  }

  public isMainCameraRecording(): boolean {
    return this.vm.bridgeGetCameraService().hasRecordingSession();
  }

  public formatRecordingClock(_uiTick: number = 0): string {
    if (this.vm.recordingWallStartMs <= 0) {
      return '00:00';
    }
    const sec = Math.max(0, Math.floor((Date.now() - this.vm.recordingWallStartMs) / 1000));
    const mm = Math.floor(sec / 60);
    const ss = sec % 60;
    const mmStr = mm < 10 ? `0${mm}` : `${mm}`;
    const ssStr = ss < 10 ? `0${ss}` : `${ss}`;
    return `${mmStr}:${ssStr}`;
  }

  public startRecordingClock(resetWallStart: boolean = true): void {
    const prevWall = this.vm.recordingWallStartMs;
    this.stopRecordingClock();
    if (resetWallStart || this.vm.recordingWallStartMs <= 0) {
      this.vm.recordingWallStartMs = Date.now();
      this.vm.recordingElapsedSec = 0;
    }
    DhDiag.info('REC',
      `recordingClock start phase=${this.vm.recordingPhase} reset=${resetWallStart ? 1 : 0} ` +
      `wall=${this.vm.recordingWallStartMs} prevWall=${prevWall}`);
    this.vm.recordingTimerId = setInterval(() => {
      this.vm.recordingElapsedSec = Math.floor((Date.now() - this.vm.recordingWallStartMs) / 1000);
      this.vm.recordingUiTick++;
      this.vm.bumpStudioUi();
    }, 500) as number;
  }

  public stopRecordingClock(): void {
    const hadTimer = this.vm.recordingTimerId >= 0;
    const elapsedSec = this.vm.recordingWallStartMs > 0 ?
      Math.floor((Date.now() - this.vm.recordingWallStartMs) / 1000) : 0;
    if (this.vm.recordingTimerId >= 0) {
      clearInterval(this.vm.recordingTimerId);
      this.vm.recordingTimerId = -1;
    }
    if (hadTimer || this.vm.recordingWallStartMs > 0) {
      DhDiag.info('REC',
        `recordingClock stop phase=${this.vm.recordingPhase} elapsedSec=${elapsedSec}`);
    }
    this.vm.recordingElapsedSec = 0;
    this.vm.recordingWallStartMs = 0;
  }
}
