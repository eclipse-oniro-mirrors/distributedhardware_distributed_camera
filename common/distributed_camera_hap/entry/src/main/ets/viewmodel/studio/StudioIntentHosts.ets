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
import { DhDiag } from '../../common/util/DhDiag';
import { CameraTarget, StreamSwitchResult, StudioMode } from '../../common/types/CameraTypes';
import { DeviceListSource, TrustDeviceInfo } from '../../common/types/DeviceTypes';
import { RemoteConnectionGuideHelper } from '../../service/RemoteConnectionGuideHelper';
import { PeerSignalService } from '../../service/PeerSignalService';
import {
  CreationIntentResult,
  ModeChangeHost,
  PhotoCaptureHost,
  PreviewConnectHost,
  VideoRecordHost
} from '../../service/switch/CreationIntentKind';
import { StudioViewModel } from './StudioViewModel';
import { StudioVmUtils } from './StudioVmUtils';

export class StudioPreviewConnectHost implements PreviewConnectHost {
  private readonly vm: StudioViewModel;

  constructor(vm: StudioViewModel) {
    this.vm = vm;
  }

  public async refreshTrustDevices(): Promise<void> {
    await this.vm.bridgeGetDmService().refreshTrustDevices();
  }

  public getBoundRemoteCount(): number {
    return this.vm.bridgeGetDmService().getBoundRemoteDevices().length;
  }

  public getDiscoveredRemoteCount(): number {
    return this.vm.bridgeGetDmService().getDiscoveredRemoteDevices().length;
  }

  public getDiscoveredDeviceName(): string {
    return this.vm.bridgeGetDmService().getDiscoveredRemoteDevices()[0]?.deviceName ?? '';
  }

  public getPrimaryBoundPeer(): TrustDeviceInfo | null {
    return this.vm.getPrimaryBoundPeer();
  }

  public isPeerTrusted(peer: TrustDeviceInfo): boolean {
    return peer.listSource === DeviceListSource.TRUSTED;
  }

  public setFallbackHint(hint: string): void {
    this.vm.fallbackHint = hint;
  }

  public beginRemoteGuide(peerName: string): void {
    this.vm.remotePeerDeviceName = peerName;
    this.vm.remoteGuideTitle = '正在连接对端镜头';
    this.vm.remoteGuideSteps = RemoteConnectionGuideHelper.buildCameraSteps(peerName);
    this.vm.showRemoteGuide = true;
    this.vm.isConnectingRemote = true;
    this.vm.fallbackHint = '';
    this.vm.bumpStudioUi();
  }

  public setRemoteGuideProgress(msg: string): void {
    this.vm.remoteGuideProgress = msg;
    this.vm.bumpStudioUi();
  }

  public markGuideDoneUntil(stepId: string): void {
    this.vm.remoteGuideSteps = RemoteConnectionGuideHelper.markDoneUntil(this.vm.remoteGuideSteps, stepId);
  }

  public markGuideAllDone(): void {
    this.vm.remoteGuideSteps = RemoteConnectionGuideHelper.markAllDone(this.vm.remoteGuideSteps);
  }

  public markGuideFailed(stepId: string): void {
    this.vm.remoteGuideSteps = RemoteConnectionGuideHelper.markAllFailed(this.vm.remoteGuideSteps, stepId);
  }

  public setShowRemoteGuide(show: boolean): void {
    this.vm.showRemoteGuide = show;
    this.vm.bumpStudioUi();
  }

  public setConnectingRemote(connecting: boolean): void {
    this.vm.isConnectingRemote = connecting;
    this.vm.bumpStudioUi();
  }

  public setRemoteGuideFailed(failed: boolean): void {
    this.vm.remoteGuideFailed = failed;
  }

  public isRemoteSessionEstablished(): boolean {
    return this.vm.bridgeIsRemoteSessionEstablished();
  }

  public setRemoteSessionEstablished(established: boolean): void {
    this.vm.bridgeSetRemoteSessionEstablished(established);
  }

  public needsColdReconnect(): boolean {
    return this.vm.coldReconnectAfterPeerRelease;
  }

  public clearColdReconnect(): void {
    this.vm.coldReconnectAfterPeerRelease = false;
  }

  public async isRemoteEnumeratedForPeer(networkId: string): Promise<boolean> {
    return this.vm.bridgeGetCameraService().isRemoteReadyForPeer(networkId);
  }

  public prewarmRemoteDh(networkId: string): void {
    this.vm.bridgeGetDhService().prewarmRemoteCamera(networkId);
  }

  public publishCameraRequest(peerName: string): void {
    PeerSignalService.getInstance().publishCameraRequest(peerName);
  }

  public stopHeartbeat(): void {
    PeerSignalService.getInstance().stopHeartbeat();
  }

  public switchToRemoteDevice(networkId: string, position: string): Promise<StreamSwitchResult> {
    return this.vm.bridgeGetSwitchController().switchToRemoteDevice(networkId, position);
  }

  public switchToRemotePhone(position: string, networkId?: string): Promise<StreamSwitchResult> {
    return this.vm.bridgeGetSwitchController().switchToRemotePhone(position, networkId);
  }

  public applySwitchResult(result: StreamSwitchResult): Promise<void> {
    return this.vm.bridgeApplySwitchResult(result);
  }

  public async refreshCameraList(): Promise<void> {
    this.vm.cameras = await this.vm.bridgeGetCameraService().enumerateCameras(true);
    this.vm.bridgeUpdateRemoteFlag();
  }

  public getConnectPeerAppWaitSec(): number {
    return AppConstants.CONNECT_PEER_APP_WAIT_SEC;
  }

  public delay(ms: number): Promise<void> {
    return StudioVmUtils.bridgeDelay(ms);
  }

  public getDefaultConnectFailHint(): string {
    return '连接失败 · 请确认：① 对端已亮屏解锁 ② 两台登录同一华为账号 ③ 对端系统弹窗点「允许使用相机」';
  }
}

export class StudioVideoRecordHost implements VideoRecordHost {
  private readonly vm: StudioViewModel;

  constructor(vm: StudioViewModel) {
    this.vm = vm;
  }

  public hasActiveCamera(): boolean {
    return this.vm.activeCamera !== null;
  }

  public getActiveCamera(): CameraTarget | null {
    return this.vm.activeCamera;
  }

  public getStudioMode(): StudioMode {
    return this.vm.studioMode;
  }

  public allocateRecordingFlowId(): number {
    return this.vm.bridgeAllocateRecordingFlowId();
  }

  public getRecordingFlowId(): number {
    return this.vm.bridgeGetRecordingFlowId();
  }

  public isRecordingStopRequested(): boolean {
    return this.vm.bridgeIsRecordingStopRequested();
  }

  public setRecordingBusy(busy: boolean): void {
    this.vm.recordingBusy = busy;
  }

  public beginRecordingUi(isRemoteMain: boolean): StudioMode {
    const prevMode = this.vm.studioMode;
    if (this.vm.recordingPhase === 'idle') {
      this.vm.recordingPhase = 'preparing';
      this.vm.isRecording = true;
      this.vm.studioMode = StudioMode.VIDEO;
      this.vm.bridgeGetOrchestrator().markRecording(true);
      DhDiag.info('REC', `beginRecordingUi preparing remote=${isRemoteMain ? 1 : 0} clock=deferred`);
    }
    this.vm.mediaHint = isRemoteMain ? '⏳ 正在准备远端录像，请稍候…' : '⏳ 正在准备录像，请稍候…';
    this.vm.fallbackHint = '';
    this.vm.recordingUiTick++;
    this.vm.bumpStudioUi();
    if (!isRemoteMain) {
      this.vm.bridgeSetRecordingRemoteMicTask(null);
    }
    return prevMode;
  }

  public setRemoteMicReadyHint(networkId: string): void {
    if (this.vm.bridgeGetAudioService().isRemoteMicRouted(networkId)) {
      this.vm.remoteMicStatusHint = '✓ 对端麦克风已就绪';
    }
  }

  public suppressPreviewMonitor(): void {
    this.vm.bridgeGetAudioService().suppressPreviewMonitor();
  }

  public setRecordingFileStamp(stamp: number): void {
    this.vm.bridgeGetCameraService().setRecordingFileStamp(stamp);
  }

  public beginRecordingRemoteMic(networkId: string, peerName: string): Promise<boolean> {
    const task: Promise<boolean> = this.vm.bridgeGetAudioService().beginRecordingRemoteMic(networkId, peerName);
    this.vm.bridgeSetRecordingRemoteMicTask(task);
    return task ?? Promise.resolve(false);
  }

  public commitRecordingModeIfNeeded(prevMode: StudioMode): void {
    if (prevMode !== StudioMode.VIDEO && this.vm.activeCamera) {
      this.vm.bridgeGetSwitchController().commitRecordingMode(this.vm.activeCamera, StudioMode.VIDEO);
    }
  }

  public prepareRecordingSession(): void {
    this.vm.bridgeGetCameraService().ensureUserStreamSpecForRecording();
    this.vm.bridgeGetCameraService().logStreamSpecMemory('beforeRecordPin');
    this.vm.bridgeGetCameraService().pinUserStreamSpecForRecording();
  }

  public startAvRecording(): Promise<boolean> {
    return this.vm.bridgeGetCameraService().toggleRecording(true);
  }

  public isCameraRecording(): boolean {
    return this.vm.bridgeGetCameraService().isRecording();
  }

  public getLastCameraHint(): string {
    return this.vm.bridgeGetCameraService().getLastPhotoHint();
  }

  public async onRecordingStarted(isRemoteMain: boolean): Promise<void> {
    this.vm.recordingPhase = 'recording';
    this.vm.bridgeStartRecordingClock(true);
    DhDiag.flowEnd('REC', 'videoRecordUi', true,
      `phase=recording remote=${isRemoteMain ? 1 : 0} cfRecording=${this.vm.bridgeGetCameraService().isRecording() ? 1 : 0}`);
    const hint: string = this.vm.bridgeGetCameraService().getLastPhotoHint();
    if (hint.length > 0) {
      this.vm.mediaHint = hint;
    }
    try {
      if (isRemoteMain) {
        await this.vm.bridgeGetAudioService().lockRecordMicForAvRecorder(true);
      }
    } catch (err) {
      DhDiag.logCatchWarn('REC', 'onRecordingStarted lockRecordMic', err);
    }
    this.vm.bridgeSyncActiveCameraFromService();
    this.vm.bridgeRefreshStreamSpecLabels();
    this.vm.bumpStudioUi();
  }

  public onRecordingStartFailed(prevMode: StudioMode, message: string): void {
    DhDiag.flowEnd('REC', 'videoRecordUi', false,
      `phase=${this.vm.recordingPhase} prevMode=${prevMode} msg=${message}`);
    this.vm.bridgeResetRecordingUiAfterFailure(prevMode);
    this.vm.mediaHint = message;
    this.vm.fallbackHint = message;
    this.vm.bumpStudioUi();
  }

  public onRecordingStartError(prevMode: StudioMode): void {
    this.vm.bridgeResetRecordingUiAfterFailure(prevMode);
    this.vm.fallbackHint = '录像启动异常';
  }

  public shouldAbortRecording(flowId: number): boolean {
    return this.vm.bridgeShouldAbortRecording(flowId);
  }

  public setRecordingStartInFlight(task: Promise<CreationIntentResult> | null): void {
    this.vm.bridgeSetRecordingStartInFlight(task);
  }

  public async maybeStartPipRecording(stamp: number): Promise<void> {
    if (!this.vm.pipOverlayVisible || !this.vm.pipPreviewActive) {
      return;
    }
    try {
      await this.vm.bridgeStartPipRecordingAsync(stamp);
    } catch (err) {
      DhDiag.logCatchWarn('REC', 'maybeStartPipRecording', err);
    }
  }
}

export class StudioModeChangeHost implements ModeChangeHost {
  private readonly vm: StudioViewModel;

  constructor(vm: StudioViewModel) {
    this.vm = vm;
  }

  public isRecordingBlocked(): boolean {
    return this.vm.isRecordingActive();
  }

  public hasActiveCamera(): boolean {
    return this.vm.activeCamera !== null;
  }

  public getStudioMode(): StudioMode {
    return this.vm.studioMode;
  }

  public hasActivePhotoSession(): boolean {
    return this.vm.bridgeGetCameraService().hasActivePhotoSession();
  }

  public setStudioMode(mode: StudioMode): void {
    this.vm.studioMode = mode;
  }

  public restoreStudioMode(mode: StudioMode): void {
    this.vm.studioMode = mode;
  }

  public switchMode(mode: StudioMode): Promise<StreamSwitchResult> {
    return this.vm.bridgeGetSwitchController().switchMode(mode);
  }

  public applySwitchResult(result: StreamSwitchResult): Promise<void> {
    return this.vm.bridgeApplySwitchResult(result);
  }

  public setFallbackHint(hint: string): void {
    this.vm.fallbackHint = hint;
  }

  public setMediaHint(hint: string): void {
    this.vm.mediaHint = hint;
  }

  public closeStudioTools(): void {
    this.vm.closeStudioTools();
  }

  public isRecording(): boolean {
    return this.vm.isRecording;
  }
}

export class StudioPhotoCaptureHost implements PhotoCaptureHost {
  private readonly vm: StudioViewModel;

  constructor(vm: StudioViewModel) {
    this.vm = vm;
  }

  public hasActiveCamera(): boolean {
    return this.vm.activeCamera !== null;
  }

  public getActiveCamera(): CameraTarget | null {
    return this.vm.activeCamera;
  }

  public isRecordingBlocked(): boolean {
    return this.vm.isRecordingActive();
  }

  public getStudioMode(): StudioMode {
    return this.vm.studioMode;
  }

  public hasActivePhotoSession(): boolean {
    return this.vm.bridgeGetCameraService().hasActivePhotoSession();
  }

  public setStudioMode(mode: StudioMode): void {
    this.vm.studioMode = mode;
  }

  public isRecordingSetupVisible(): boolean {
    return this.vm.showRecordingSetup;
  }

  public dismissRecordingSetup(): void {
    this.vm.dismissRecordingSetup();
  }

  public changeMode(mode: StudioMode): Promise<void> {
    return this.vm.changeMode(mode);
  }

  public syncActiveCamera(): void {
    this.vm.bridgeSyncActiveCameraFromService();
  }

  public promptLensSelection(): void {
    this.vm.promptLensSelection();
  }

  public holdPreviewMonitor(ms: number): void {
    this.vm.bridgeGetAudioService().holdPreviewMonitor(ms);
  }

  public resumePreviewMonitor(): void {
    this.vm.bridgeGetAudioService().resumePreviewMonitor();
  }

  public setMediaHint(hint: string): void {
    this.vm.mediaHint = hint;
  }

  public setFallbackHint(hint: string): void {
    this.vm.fallbackHint = hint;
  }

  public getMediaHint(): string {
    return this.vm.mediaHint;
  }

  public onPhotoSaveResult(cb: (message: string, success: boolean) => void): void {
    this.vm.bridgeGetCameraService().onPhotoSaveResult(cb);
  }

  public offPhotoSaveResult(): void {
    this.vm.bridgeGetCameraService().offPhotoSaveResult();
  }

  public takePhoto(): Promise<boolean> {
    this.vm.bridgeSyncActiveCameraFromService();
    return this.vm.bridgeGetCameraService().takePhoto();
  }

  public getLastPhotoHint(): string {
    return this.vm.bridgeGetCameraService().getLastPhotoHint();
  }

  public ensurePreviewMonitor(): void {
    void this.vm.bridgeGetAudioService().ensurePreviewMonitorForStudio();
  }

  public delay(ms: number): Promise<void> {
    return StudioVmUtils.bridgeDelay(ms);
  }
}
