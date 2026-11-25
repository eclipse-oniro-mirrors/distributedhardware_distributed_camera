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
import { CameraSourceType, StudioMode } from '../../common/types/CameraTypes';
import { DhDiag } from '../../common/util/DhDiag';
import { StudioViewModel } from './StudioViewModel';

/** 创作台：分辨率/帧率/变焦/对焦 — 从 StudioViewModel 拆出以满足 ≤1800 行 */
export class StudioStreamSpecSection {
  private readonly vm: StudioViewModel;

  constructor(vm: StudioViewModel) {
    this.vm = vm;
  }


  public refreshStreamSpecLabels(): void {
    this.refreshStreamSpecLabelsForRecordingSetup();
    this.refreshZoomUi();
    this.refreshFocusUi();
  }

  /** CameraManager 控制项就绪后刷新变焦/对焦 UI */
  public refreshCameraControlsUi(): void {
    this.refreshZoomUi();
    this.refreshFocusUi();
  }

  /** 录像设置弹层：只同步分辨率/帧率选项，不刷新变焦/对焦（避免挡住弹层首帧） */
  public refreshStreamSpecLabelsForRecordingSetup(): void {
    this.vm.streamResolutionLabel = this.vm.bridgeGetCameraService().getStreamResolutionLabel();
    this.vm.streamFrameRateLabel = this.vm.bridgeGetCameraService().getStreamFrameRateLabel();
    this.vm.streamResolutionOptions = this.vm.bridgeGetCameraService().getResolutionOptions();
    this.vm.streamFpsOptions = this.vm.bridgeGetCameraService().getFrameRateOptions();
    this.vm.selectedResolutionIndex = this.vm.bridgeGetCameraService().getResolutionIndex();
    this.vm.selectedFpsIndex = this.vm.bridgeGetCameraService().getFpsIndex();
    if (this.vm.streamFpsOptions.length > 0) {
      const idx = Math.min(Math.max(0, this.vm.selectedFpsIndex), this.vm.streamFpsOptions.length - 1);
      this.vm.selectedFpsIndex = idx;
      this.vm.selectedFpsValue = this.vm.streamFpsOptions[idx].fps;
    }
    this.vm.streamSpecUiTick++;
    const remote = this.vm.activeCamera?.sourceType === CameraSourceType.DISTRIBUTED ? 1 : 0;
    DhDiag.info('VM',
      `streamSpec refresh res=${this.vm.streamResolutionOptions.length} fps=${this.vm.streamFpsOptions.length} ` +
      `resIdx=${this.vm.selectedResolutionIndex} fpsVal=${this.vm.selectedFpsValue} remote=${remote} ` +
      `tick=${this.vm.streamSpecUiTick} label=${this.vm.streamResolutionLabel}`);
  }

  private refreshZoomUi(syncSelectedStop: boolean = true): void {
    const zoom = this.vm.bridgeGetCameraService().getZoomCapability();
    this.vm.zoomSupported = zoom.supported;
    this.vm.zoomMinRatio = zoom.minRatio;
    this.vm.zoomMaxRatio = zoom.maxRatio;
    this.vm.zoomRatio = zoom.currentRatio;
    if (syncSelectedStop) {
      this.syncSelectedZoomStopFromRatio();
    }
    this.vm.bumpStudioUi();
  }

  private syncSelectedZoomStopFromRatio(): void {
    const nearest = this.nearestPreviewZoomStop(this.vm.zoomRatio);
    if (nearest > 0) {
      this.vm.selectedPreviewZoomStop = nearest;
    }
  }

  private nearestPreviewZoomStop(ratio: number): number {
    const stops = this.getPreviewZoomStops();
    if (stops.length === 0) {
      return ratio;
    }
    let nearest = stops[0];
    let bestDiff = Math.abs(stops[0] - ratio);
    for (let i = 1; i < stops.length; i++) {
      const diff = Math.abs(stops[i] - ratio);
      if (diff < bestDiff) {
        bestDiff = diff;
        nearest = stops[i];
      }
    }
    return nearest;
  }

  private refreshFocusUi(): void {
    const focus = this.vm.bridgeGetCameraService().getFocusCapability();
    this.vm.focusSupported = focus.supported;
    this.vm.tapFocusSupported = focus.tapToFocusSupported;
    this.vm.focusModeLabel = focus.modeLabel;
    this.updateFocusStatusHint();
  }

  private updateFocusStatusHint(): void {
    if (!this.vm.focusSupported && !this.vm.zoomSupported) {
      this.vm.focusStatusHint = '当前镜头不支持对焦与变焦';
      return;
    }
    const parts: string[] = [];
    if (this.vm.focusSupported && this.vm.tapFocusSupported) {
      parts.push('点击画面对焦');
    } else if (this.vm.focusSupported) {
      parts.push(this.vm.focusModeLabel);
    }
    this.vm.focusStatusHint = parts.length > 0 ? parts.join(' · ') : '';
  }

  public async selectStreamResolutionAt(index: number): Promise<void> {
    if (this.vm.isRecordingActive()) {
      this.vm.fallbackHint = '录像中无法切换分辨率，请先停止录像';
      return;
    }
    this.vm.bridgeGetCameraService().stageUserStreamSpec(index, this.vm.selectedFpsIndex);
    const ok = await this.vm.bridgeGetCameraService().applySelectedResolutionAt(index);
    this.refreshStreamSpecLabels();
    if (ok) {
      const specHint = this.vm.bridgeGetCameraService().getLastPhotoHint();
      this.vm.mediaHint = specHint.length > 0 ?
        `已选分辨率 · ${this.vm.streamResolutionLabel}（${specHint}）` :
        `已选分辨率 · ${this.vm.streamResolutionLabel} · ${this.vm.streamFrameRateLabel}`;
      this.vm.fallbackHint = '';
    } else {
      this.vm.fallbackHint = this.vm.bridgeGetCameraService().getLastPhotoHint() || '分辨率切换失败';
    }
  }

  public async selectStreamFrameRateAt(index: number): Promise<void> {
    if (this.vm.isRecordingActive()) {
      this.vm.fallbackHint = '录像中无法切换帧率，请先停止录像';
      return;
    }
    this.vm.bridgeGetCameraService().stageUserStreamSpec(this.vm.selectedResolutionIndex, index);
    const ok = await this.vm.bridgeGetCameraService().applySelectedFrameRateAt(index);
    this.refreshStreamSpecLabels();
    if (ok) {
      const hint = this.vm.bridgeGetCameraService().getLastPhotoHint();
      this.vm.mediaHint = hint.length > 0 ? hint :
        `已选帧率 · 预览 ${this.vm.streamFrameRateLabel} · ${this.vm.streamResolutionLabel}`;
      this.vm.fallbackHint = '';
    } else {
      this.vm.fallbackHint = this.vm.bridgeGetCameraService().getLastPhotoHint() || '帧率切换失败';
    }
  }

  public async selectStreamFrameRateFps(fps: number): Promise<void> {
    if (this.vm.isRecordingActive()) {
      this.vm.fallbackHint = '录像中无法切换帧率，请先停止录像';
      return;
    }
    const rounded = Math.round(fps);
    if (!this.vm.bridgeGetCameraService().isFpsOptionSupported(rounded)) {
      this.vm.fallbackHint = `当前分辨率不支持 ${rounded} fps`;
      return;
    }
    const fpsIdx = this.vm.streamFpsOptions.findIndex(o => o.fps === rounded);
    this.vm.bridgeGetCameraService().stageUserStreamSpec(this.vm.selectedResolutionIndex,
      fpsIdx >= 0 ? fpsIdx : this.vm.selectedFpsIndex);
    const ok = await this.vm.bridgeGetCameraService().applyFrameRateFps(rounded);
    this.refreshStreamSpecLabels();
    if (ok) {
      this.vm.selectedFpsValue = rounded;
      const hint = this.vm.bridgeGetCameraService().getLastPhotoHint();
      this.vm.mediaHint = hint.length > 0 ? hint :
        `已选帧率 · 预览 ${this.vm.streamFrameRateLabel} · ${this.vm.streamResolutionLabel}`;
      this.vm.fallbackHint = '';
    } else if (this.vm.bridgeGetCameraService().getLastPhotoHint().length > 0) {
      this.vm.fallbackHint = this.vm.bridgeGetCameraService().getLastPhotoHint();
    }
  }

  /** 预览区变焦（拍照/录像中可用） */
  public async setPreviewZoomRatio(ratio: number, smooth: boolean = false): Promise<void> {
    if (!this.vm.activeCamera) {
      return;
    }
    if (!this.vm.zoomSupported && !this.vm.bridgeGetCameraService().ensureZoomCapabilityReady()) {
      return;
    }
    const clamped = this.clampPreviewZoomRatio(ratio);
    this.vm.selectedPreviewZoomStop = this.nearestPreviewZoomStop(clamped);
    this.vm.zoomRatio = clamped;
    this.vm.bumpStudioUi();
    const ok = smooth ?
      await this.vm.bridgeGetCameraService().setSmoothZoomRatio(clamped) :
      await this.vm.bridgeGetCameraService().setZoomRatio(clamped);
    if (ok) {
      this.vm.zoomRatio = clamped;
      this.vm.selectedPreviewZoomStop = this.nearestPreviewZoomStop(clamped);
      this.vm.fallbackHint = '';
      this.vm.bumpStudioUi();
    } else {
      this.refreshZoomUi(true);
      this.vm.bumpStudioUi();
      if (this.vm.bridgeGetCameraService().getLastPhotoHint().length > 0) {
        this.vm.fallbackHint = this.vm.bridgeGetCameraService().getLastPhotoHint();
      }
    }
  }

  /** 拖动焦段尺 — 即时更新 UI，底层走 SmoothZoom */
  public dragPreviewZoomRatio(ratio: number): void {
    if (!this.vm.activeCamera) {
      return;
    }
    if (!this.vm.zoomSupported && !this.vm.bridgeGetCameraService().ensureZoomCapabilityReady()) {
      return;
    }
    const clamped = this.clampPreviewZoomRatio(ratio);
    this.vm.zoomRatio = clamped;
    this.vm.selectedPreviewZoomStop = this.nearestPreviewZoomStop(clamped);
    this.vm.bumpStudioUi();
    void this.vm.bridgeGetCameraService().setSmoothZoomRatio(clamped);
  }

  public getPreviewZoomUiMin(): number {
    if (!this.vm.zoomSupported) {
      return AppConstants.PREVIEW_ZOOM_UI_MIN;
    }
    return Math.max(AppConstants.PREVIEW_ZOOM_UI_MIN, this.vm.zoomMinRatio);
  }

  public getPreviewZoomUiMax(): number {
    if (!this.vm.zoomSupported) {
      return AppConstants.PREVIEW_ZOOM_UI_MAX;
    }
    return Math.min(AppConstants.PREVIEW_ZOOM_UI_MAX, this.vm.zoomMaxRatio);
  }

  public clampPreviewZoomRatio(ratio: number): number {
    const uiMin = this.getPreviewZoomUiMin();
    const uiMax = this.getPreviewZoomUiMax();
    const uiClamped = Math.min(uiMax, Math.max(uiMin, ratio));
    return Math.min(this.vm.zoomMaxRatio, Math.max(this.vm.zoomMinRatio, uiClamped));
  }

  public formatZoomStopLabel(ratio: number): string {
    if (ratio >= this.getPreviewZoomUiMax() - 0.05) {
      return `${this.getPreviewZoomUiMax().toFixed(0)}×`;
    }
    if (Math.abs(ratio - Math.round(ratio)) < 0.08) {
      return `${Math.round(ratio)}×`;
    }
    return `${ratio.toFixed(1)}×`;
  }

  public formatPreviewZoomLabel(): string {
    return this.formatZoomStopLabel(this.vm.zoomRatio);
  }

  public togglePreviewGrid(): void {
    this.vm.previewGridEnabled = !this.vm.previewGridEnabled;
  }

  public getPreviewZoomStops(): number[] {
    const stops = AppConstants.PREVIEW_ZOOM_STOPS;
    if (!this.vm.zoomSupported || this.vm.zoomMaxRatio <= this.vm.zoomMinRatio + 0.01) {
      return stops;
    }
    return stops.filter(
      stop => stop >= this.vm.zoomMinRatio - 0.01 && stop <= this.vm.zoomMaxRatio + 0.01);
  }

  public isPreviewZoomStopActive(stop: number): boolean {
    return this.vm.selectedPreviewZoomStop === stop;
  }

  public selectPreviewZoomStop(stop: number): void {
    void this.applyPreviewZoomStop(stop);
  }

  private async applyPreviewZoomStop(stop: number): Promise<void> {
    DhDiag.info('VM', `selectPreviewZoomStop ${stop}x`);
    if (!this.vm.zoomSupported) {
      this.vm.bridgeGetCameraService().ensureZoomCapabilityReady();
      this.refreshZoomUi(true);
    }
    if (!this.vm.zoomSupported) {
      return;
    }
    await this.setPreviewZoomRatio(stop, false);
  }

  private showFocusIndicator(localX: number, localY: number): void {
    this.vm.focusIndicatorX = localX;
    this.vm.focusIndicatorY = localY;
    this.vm.focusIndicatorVisible = true;
    if (this.vm.focusIndicatorTimer >= 0) {
      clearTimeout(this.vm.focusIndicatorTimer);
    }
    this.vm.focusIndicatorTimer = setTimeout(() => {
      this.vm.focusIndicatorVisible = false;
      this.vm.focusIndicatorTimer = -1;
    }, AppConstants.FOCUS_INDICATOR_FADE_MS) as number;
  }

  public async onPreviewTapFocus(localX: number, localY: number, areaW: number, areaH: number): Promise<void> {
    if (!this.vm.activeCamera) {
      return;
    }
    if (!this.vm.tapFocusSupported) {
      this.vm.focusStatusHint = this.vm.focusSupported ?
        `${this.vm.focusModeLabel}（不支持点选）` : '当前镜头不支持对焦';
      return;
    }
    const ok = await this.vm.bridgeGetCameraService().focusAtPreviewTap(localX, localY, areaW, areaH);
    if (ok) {
      this.showFocusIndicator(localX, localY);
      this.vm.focusStatusHint = this.vm.bridgeGetCameraService().getLastPhotoHint();
      this.vm.mediaHint = '已更新对焦点';
      this.vm.fallbackHint = '';
      setTimeout(() => {
        void this.vm.bridgeGetCameraService().restorePreviewFocusMode().then(() => {
          this.refreshStreamSpecLabels();
        }).catch((err: Error) => {
          DhDiag.warn('VM', `restorePreviewFocusMode failed ${JSON.stringify(err)}`);
        });
      }, 2500) as number;
    } else if (this.vm.bridgeGetCameraService().getLastPhotoHint().length > 0) {
      this.vm.focusStatusHint = this.vm.bridgeGetCameraService().getLastPhotoHint();
    }
  }

  public isStreamFpsSupported(fps: number): boolean {
    return this.vm.bridgeGetCameraService().isFpsOptionSupported(Math.round(fps));
  }

  /** 某档分辨率支持的帧率摘要，如「30 · 60 fps」 */
  public resolutionFpsSummary(index: number): string {
    const fps = this.vm.bridgeGetCameraService().getSupportedFpsForResolutionIndex(index);
    if (fps.length === 0) {
      return '— fps';
    }
    return `${fps.join(' · ')} fps`;
  }

  /** 当前选中分辨率下的可选帧率列表 */
  public currentResolutionSupportedFps(): number[] {
    return this.vm.bridgeGetCameraService().getSupportedFpsForResolutionIndex(this.vm.selectedResolutionIndex);
  }

  public canChangeStreamSpec(): boolean {
    return this.vm.activeCamera !== null && !this.vm.isRecordingActive();
  }

  public isRemoteMainCamera(): boolean {
    return this.vm.activeCamera?.sourceType === CameraSourceType.DISTRIBUTED;
  }

  public remoteStreamSpecHint(): string {
    return '远端换分辨率将重建 DH 通道（数秒黑屏）· 帧率由开流协商';
  }

  public canChangeStreamFrameRate(): boolean {
    return !this.isRemoteMainCamera();
  }

  public isStreamSpecChanging(): boolean {
    return this.vm.bridgeGetCameraService().isPreviewSpecChanging();
  }

  public getResolutionSelectOptions(): SelectOption[] {
    const result: SelectOption[] = [];
    for (let i = 0; i < this.vm.streamResolutionOptions.length; i++) {
      const opt = this.vm.streamResolutionOptions[i];
      result.push({ value: opt.label });
    }
    if (result.length === 0) {
      result.push({ value: '无可用分辨率' });
    }
    return result;
  }

  public getFpsSelectOptions(): SelectOption[] {
    if (this.vm.streamFpsOptions.length === 0) {
      return [{ value: '无可用帧率' }];
    }
    const result: SelectOption[] = [];
    for (const opt of this.vm.streamFpsOptions) {
      result.push({ value: `${opt.fps} fps` });
    }
    return result;
  }

  public currentResolutionSelectValue(): string {
    const opts = this.getResolutionSelectOptions();
    const idx = Math.min(this.vm.selectedResolutionIndex, opts.length - 1);
    return idx >= 0 ? opts[idx].value as string : '分辨率';
  }

  public currentFpsSelectValue(): string {
    if (this.vm.selectedFpsValue > 0 && this.vm.selectedFpsValue <= AppConstants.FPS_UI_MAX) {
      return `${this.vm.selectedFpsValue} fps`;
    }
    const opts = this.getFpsSelectOptions();
    const idx = Math.min(this.vm.selectedFpsIndex, opts.length - 1);
    return idx >= 0 ? opts[idx].value as string : '帧率';
  }

  public async cycleStreamResolution(): Promise<void> {
    if (this.vm.isRecordingActive()) {
      this.vm.fallbackHint = '录像中无法切换分辨率，请先停止录像';
      return;
    }
    const ok = await this.vm.bridgeGetCameraService().cycleSelectedResolution();
    this.refreshStreamSpecLabels();
    if (ok) {
      const specHint = this.vm.bridgeGetCameraService().getLastPhotoHint();
      this.vm.mediaHint = specHint.length > 0 ?
        `已切换分辨率 · ${this.vm.streamResolutionLabel}（${specHint}）` :
        `已切换分辨率 · ${this.vm.streamResolutionLabel} · ${this.vm.streamFrameRateLabel}`;
      this.vm.fallbackHint = '';
    } else if (this.vm.bridgeGetCameraService().getLastPhotoHint().length > 0) {
      this.vm.fallbackHint = this.vm.bridgeGetCameraService().getLastPhotoHint();
    }
    if (ok) {
      this.vm.closeStudioTools();
    }
  }

  public async cycleStreamFrameRate(): Promise<void> {
    if (this.vm.isRecordingActive()) {
      this.vm.fallbackHint = '录像中无法切换帧率，请先停止录像';
      return;
    }
    const ok = await this.vm.bridgeGetCameraService().cycleSelectedFrameRate();
    this.refreshStreamSpecLabels();
    if (ok) {
      this.vm.mediaHint = `已切换帧率 · ${this.vm.streamFrameRateLabel} · ${this.vm.streamResolutionLabel}`;
      this.vm.fallbackHint = '';
    } else if (this.vm.bridgeGetCameraService().getLastPhotoHint().length > 0) {
      this.vm.fallbackHint = this.vm.bridgeGetCameraService().getLastPhotoHint();
    }
    if (ok) {
      this.vm.closeStudioTools();
    }
  }
}
