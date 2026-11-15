import React from 'react';
import { PARAMS, HaloParamDef } from '../utils/haloParams';

interface ConsoleDrawerProps {
  open: boolean;
  values: Record<string, number>;
  onChangeParam: (key: string, val: number, rebuild?: HaloParamDef['rebuild']) => void;
  onReset: () => void;
  onClose: () => void;
}

const GROUPS = Array.from(new Set(PARAMS.map((p) => p.group)));

export const ConsoleDrawer: React.FC<ConsoleDrawerProps> = ({
  open,
  values,
  onChangeParam,
  onReset,
  onClose,
}) => {
  return (
    <aside id="cpanel" className={open ? 'open' : ''} aria-label="HALOFLUX 参数控制台">
      <div className="top">
        <b>HALOFLUX CONSOLE</b>
        <button id="cReset" type="button" onClick={onReset}>
          恢复默认
        </button>
        <button id="cClose" type="button" onClick={onClose} aria-label="关闭控制台">
          ✕
        </button>
      </div>
      <div className="body">
        {GROUPS.map((group, gi) => (
          <details key={group} open={gi < 2}>
            <summary>{group}</summary>
            {PARAMS.filter((p) => p.group === group).map((p) => {
              const v = values[p.key] ?? 0;
              return (
                <div className="row" key={p.key} data-k={p.key}>
                  <label htmlFor={`param-${p.key}`}>{p.label}</label>
                  <input
                    id={`param-${p.key}`}
                    type="range"
                    min={p.min}
                    max={p.max}
                    step={p.step}
                    value={v}
                    onChange={(e) => {
                      const num = parseFloat(e.target.value);
                      if (!Number.isNaN(num)) {
                        onChangeParam(p.key, num, p.rebuild);
                      }
                    }}
                  />
                  <input
                    type="number"
                    min={p.min}
                    max={p.max}
                    step={p.step}
                    value={v}
                    aria-label={`${p.label} 数值`}
                    onChange={(e) => {
                      const num = parseFloat(e.target.value);
                      if (!Number.isNaN(num)) {
                        onChangeParam(p.key, num, p.rebuild);
                      }
                    }}
                  />
                </div>
              );
            })}
          </details>
        ))}
      </div>
    </aside>
  );
};
