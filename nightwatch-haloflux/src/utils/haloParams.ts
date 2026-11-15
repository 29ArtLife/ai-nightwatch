export type ParamRebuildKind = 'resize' | 'web' | 'slots' | 'flyers';

export interface HaloParamDef {
  key: string;
  label: string;
  min: number;
  max: number;
  step: number;
  group: string;
  rebuild?: ParamRebuildKind;
}

export const PARAMS: HaloParamDef[] = [
  { key: 'tempo', label: '整体节拍速度', min: 0.4, max: 2.5, step: 0.05, group: '全局' },
  { key: 'camera', label: '自动运镜 (0关 1开)', min: 0, max: 1, step: 1, group: '全局' },
  { key: 'camZoom', label: '运镜推近幅度', min: 0, max: 2, step: 0.05, group: '全局' },
  { key: 'glow', label: '柔光层强度', min: 0, max: 1.5, step: 0.05, group: '全局' },
  { key: 'scan', label: '扫描线 (0关 1开)', min: 0, max: 1, step: 1, group: '全局' },
  { key: 'ringSpeed', label: '圆环转动幅度/速度', min: 0, max: 3, step: 0.05, group: '圆环' },
  { key: 'ringPause', label: '圆环停顿时长', min: 0, max: 3, step: 0.05, group: '圆环' },
  { key: 'ringWidth', label: '环带厚度', min: 0.6, max: 1.6, step: 0.02, group: '圆环', rebuild: 'resize' },
  { key: 'rimBright', label: '内外缘细线亮度', min: 0, max: 2, step: 0.05, group: '圆环' },
  { key: 'rimWidth', label: '内外缘细线带宽度', min: 0.3, max: 2.5, step: 0.05, group: '圆环', rebuild: 'slots' },
  { key: 'dataFlicker', label: '数据块刷新/闪烁', min: 0, max: 4, step: 0.1, group: '圆环' },
  { key: 'rimDensity', label: '内外缘细线 密度', min: 0.3, max: 3, step: 0.05, group: '圆环' },
  { key: 'webBright', label: '底层网线亮度', min: 0.1, max: 3, step: 0.05, group: '圈内', rebuild: 'web' },
  { key: 'webPulseBase', label: '网线闪烁层基础亮度', min: 0, max: 1, step: 0.02, group: '圈内' },
  { key: 'webPulseAmp', label: '网线闪烁层节拍亮度', min: 0, max: 1, step: 0.02, group: '圈内' },
  { key: 'webSpin', label: '网线整体转速', min: 0, max: 5, step: 0.1, group: '圈内' },
  { key: 'runnerCount', label: '单独亮线 数量', min: 0, max: 900, step: 1, group: '圈内' },
  { key: 'runnerBright', label: '单独亮线 亮度', min: 0, max: 2, step: 0.05, group: '圈内' },
  { key: 'runnerWidth', label: '单独亮线 粗细', min: 0.3, max: 3, step: 0.05, group: '圈内' },
  { key: 'runnerSpeed', label: '单独亮线 速度', min: 0.1, max: 4, step: 0.05, group: '圈内' },
  { key: 'runnerVariety', label: '单独亮线 速度差异', min: 0, max: 1, step: 0.05, group: '圈内' },
  { key: 'cometPerBeat', label: '成组光束 每拍数量', min: 0, max: 6, step: 0.1, group: '圈内' },
  { key: 'cometBurst', label: '成组光束 重拍爆发数', min: 0, max: 12, step: 0.5, group: '圈内' },
  { key: 'cometTrickle', label: '成组光束 拍间零星(每秒)', min: 0, max: 6, step: 0.1, group: '圈内' },
  { key: 'cometLines', label: '成组光束 每组线数', min: 0.3, max: 3, step: 0.05, group: '圈内' },
  { key: 'cometWidth', label: '成组光束 宽度', min: 0.3, max: 3, step: 0.05, group: '圈内' },
  { key: 'cometBright', label: '成组光束 亮度', min: 0.1, max: 2.5, step: 0.05, group: '圈内' },
  { key: 'cometGlow', label: '成组光束 柔光', min: 0, max: 3, step: 0.05, group: '圈内' },
  { key: 'cometSpeed', label: '成组光束 速度', min: 0.3, max: 3, step: 0.05, group: '圈内' },
  { key: 'cometFollow', label: '成组光束 跟随圆环 (0/1)', min: 0, max: 1, step: 1, group: '圈内' },
  { key: 'beamBright', label: '伸缩光束 亮度', min: 0, max: 2.5, step: 0.05, group: '环外' },
  { key: 'beamLen', label: '伸缩光束 长度', min: 0.2, max: 1.8, step: 0.05, group: '环外' },
  { key: 'beamWidth', label: '伸缩光束 线粗细', min: 0.3, max: 3, step: 0.05, group: '环外' },
  { key: 'beamBounce', label: '回弹波浪层 强度', min: 0, max: 2, step: 0.05, group: '环外' },
  { key: 'beamGlow', label: '伸缩光束 柔光', min: 0, max: 6, step: 0.1, group: '环外' },
  { key: 'dashBright', label: '流动短线 亮度', min: 0, max: 2, step: 0.05, group: '环外' },
  { key: 'hazeCount', label: '宽光带 数量', min: 0, max: 30, step: 1, group: '环外' },
  { key: 'hazeBright', label: '宽光带 亮度', min: 0, max: 3, step: 0.05, group: '环外' },
  { key: 'flyerCount', label: '飞出流线(单独) 数量', min: 0, max: 3, step: 0.05, group: '环外', rebuild: 'flyers' },
  { key: 'flyerBright', label: '飞出流线(单独) 亮度', min: 0, max: 3, step: 0.05, group: '环外' },
  { key: 'flyerWidth', label: '飞出流线 粗细', min: 0.3, max: 3, step: 0.05, group: '环外' },
  { key: 'flyerSpeed', label: '飞出流线 速度', min: 0.2, max: 3, step: 0.05, group: '环外' },
  { key: 'burstRate', label: '飞出流线(成组) 频率', min: 0, max: 5, step: 0.1, group: '环外' },
  { key: 'burstSize', label: '飞出流线(成组) 每组数量', min: 0.2, max: 3, step: 0.05, group: '环外' },
  { key: 'burstBright', label: '飞出流线(成组) 亮度', min: 0, max: 2.5, step: 0.05, group: '环外' },
  { key: 'flareRate', label: '根部闪光 频率', min: 0, max: 5, step: 0.1, group: '环外' },
  { key: 'flareBright', label: '根部闪光 亮度', min: 0, max: 2, step: 0.05, group: '环外' },
  { key: 'depthBlur', label: '远景虚化 (环外远层)', min: 0, max: 5, step: 0.1, group: '空间层次' },
  { key: 'depthDim', label: '远景亮度', min: 0, max: 1.5, step: 0.05, group: '空间层次' },
  { key: 'webBlur', label: '圈内底层虚化', min: 0, max: 4, step: 0.1, group: '空间层次', rebuild: 'web' },
  { key: 'parallax', label: '视差 (运镜时远近错位)', min: 0, max: 1.5, step: 0.05, group: '空间层次' },
  { key: 'bokeh', label: '前景光斑 数量', min: 0, max: 80, step: 1, group: '空间层次' },
  { key: 'bokehBright', label: '前景光斑 亮度', min: 0, max: 3, step: 0.05, group: '空间层次' },
  { key: 'atmos', label: '空间雾气', min: 0, max: 3, step: 0.05, group: '空间层次' },
  { key: 'ringShadow', label: '圆环遮挡阴影', min: 0, max: 2, step: 0.05, group: '空间层次' },
  { key: 'vignette', label: '暗角', min: 0, max: 1.5, step: 0.05, group: '空间层次' },
];

export const BAKED_MINE: Record<string, number> = {
  tempo: 1.45,
  camera: 1,
  camZoom: 0.65,
  glow: 1.1,
  scan: 1,
  ringSpeed: 1.8,
  ringPause: 1.2,
  ringWidth: 1.25,
  rimBright: 1.6,
  rimWidth: 1.25,
  dataFlicker: 1,
  webBright: 0.9,
  webPulseBase: 0.1,
  webPulseAmp: 0.8,
  webSpin: 1,
  runnerCount: 540,
  runnerBright: 0.6,
  runnerWidth: 1,
  runnerSpeed: 0.7,
  runnerVariety: 0.4,
  cometPerBeat: 1.6,
  cometBurst: 6,
  cometTrickle: 1.0,
  cometLines: 1,
  cometWidth: 1,
  cometBright: 1,
  cometGlow: 1.1,
  cometSpeed: 0.9,
  cometFollow: 1,
  beamBright: 1.5,
  beamLen: 1.5,
  beamWidth: 0.75,
  beamBounce: 1.6,
  beamGlow: 2.6,
  dashBright: 1.6,
  hazeCount: 18,
  hazeBright: 1.3,
  flyerCount: 2.2,
  flyerBright: 2.4,
  flyerWidth: 1.3,
  flyerSpeed: 1.8,
  burstRate: 2.2,
  burstSize: 2.0,
  burstBright: 2.0,
  flareRate: 2.5,
  flareBright: 1.7,
  rimDensity: 1.2,
  depthBlur: 0,
  depthDim: 0.15,
  webBlur: 0,
  parallax: 0,
  bokeh: 0,
  bokehBright: 0,
  atmos: 0.4,
  ringShadow: 0.5,
  vignette: 0.35,
};

/**
 * Web Audio Tactical SFX & Procedural Ambient BGM Synthesizer
 */
export const SFX = (() => {
  let ctx: AudioContext | null = null;
  let on = false;
  let bgmOn = false;
  let bgmGain: GainNode | null = null;
  let bgmTimer: number | null = null;
  let bgmVol = 0.45;

  const ensure = () => {
    if (typeof window === 'undefined') return null;
    if (!ctx) {
      const AC = window.AudioContext || (window as any).webkitAudioContext;
      if (AC) ctx = new AC();
    }
    if (ctx && ctx.state === 'suspended') {
      ctx.resume().catch(() => {});
    }
    return ctx;
  };

  function tone(
    freq: number,
    dur: number,
    type: OscillatorType = 'sine',
    gain = 0.06,
    slideTo: number | null = null
  ) {
    if (!on) return;
    const c = ensure();
    if (!c) return;
    const o = c.createOscillator();
    const g = c.createGain();
    o.type = type;
    o.frequency.setValueAtTime(freq, c.currentTime);
    if (slideTo) {
      o.frequency.exponentialRampToValueAtTime(slideTo, c.currentTime + dur);
    }
    g.gain.setValueAtTime(gain, c.currentTime);
    g.gain.exponentialRampToValueAtTime(0.0001, c.currentTime + dur);
    o.connect(g);
    g.connect(c.destination);
    o.start();
    o.stop(c.currentTime + dur);
  }

  function scheduleBgmPulse() {
    if (!bgmOn) return;
    const c = ensure();
    if (!c) return;
    if (!bgmGain) {
      bgmGain = c.createGain();
      bgmGain.gain.value = bgmVol * 0.14;
      bgmGain.connect(c.destination);
    }
    const notes = [55, 65.41, 73.42, 82.41, 98.0, 110.0, 130.81, 146.83];
    const f = notes[Math.floor(Math.random() * notes.length)];
    const o = c.createOscillator();
    const g = c.createGain();
    o.type = Math.random() < 0.5 ? 'triangle' : 'sine';
    o.frequency.setValueAtTime(f, c.currentTime);
    g.gain.setValueAtTime(0.001, c.currentTime);
    g.gain.linearRampToValueAtTime(0.22, c.currentTime + 0.15);
    g.gain.exponentialRampToValueAtTime(0.0008, c.currentTime + 1.4);
    o.connect(g);
    g.connect(bgmGain);
    o.start();
    o.stop(c.currentTime + 1.45);
  }

  return {
    get enabled() {
      return on;
    },
    get bgmEnabled() {
      return bgmOn;
    },
    toggle() {
      on = !on;
      if (on) tone(660, 0.08, 'triangle', 0.05, 880);
      return on;
    },
    toggleBgm() {
      bgmOn = !bgmOn;
      if (bgmOn) {
        scheduleBgmPulse();
        bgmTimer = window.setInterval(scheduleBgmPulse, 620);
      } else if (bgmTimer) {
        clearInterval(bgmTimer);
        bgmTimer = null;
      }
      return bgmOn;
    },
    setBgmVolume(val0to100: number) {
      bgmVol = Math.pow(val0to100 / 100, 1.6);
      if (bgmGain && ctx) {
        bgmGain.gain.setValueAtTime(bgmVol * 0.14, ctx.currentTime);
      }
    },
    attack() {
      tone(320, 0.07, 'sawtooth', 0.03, 180);
    },
    ai() {
      tone(520, 0.12, 'sine', 0.04, 780);
    },
    ban() {
      tone(140, 0.35, 'triangle', 0.11, 42);
      tone(880, 0.14, 'sine', 0.04, 440);
    },
    unban() {
      tone(440, 0.16, 'sine', 0.04, 880);
    },
  };
})();
