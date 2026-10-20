export interface StreamMetricsData {
  switchStartMs: number;
  switchEndMs: number;
  firstFrameMs: number;
  audioPulseMs: number;
  frameCount: number;
  switchSuccess: boolean;
}

/** 重置切流指标 */
export const resetMetrics: () => void;

/** 标记切流开始 */
export const markSwitchStart: () => void;

/** 标记首帧到达 */
export const markFirstFrame: () => void;

/** 标记切流结束 */
export const markSwitchEnd: (success: boolean) => void;

/** 标记音频脉冲（试播起点，供切流指标关联） */
export const markAudioPulse: () => void;

/** 获取当前切流指标 */
export const getMetrics: () => StreamMetricsData;
