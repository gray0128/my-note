import { mountCandidateA, CandidateAHandle } from "./candidateA";
import { mountCandidateB, CandidateBHandle } from "./candidateB";
import { makeSampleBlocks, makeStressBlocks } from "./model";

declare global {
  interface Window {
    spikeApi: {
      mountA(opts?: { vimMode?: boolean; stressCount?: number; virtualize?: boolean }): { mountMs: number; domNodes: number };
      mountB(opts?: { vimMode?: boolean; stressCount?: number }): { mountMs: number; domNodes: number };
      handleA?: CandidateAHandle;
      handleB?: CandidateBHandle;
    };
  }
}

const rootA = document.getElementById("root-a")!;
const rootB = document.getElementById("root-b")!;

window.spikeApi = {
  mountA(opts = {}) {
    window.spikeApi.handleA?.destroy();
    const blocks = opts.stressCount ? makeStressBlocks(opts.stressCount) : makeSampleBlocks();
    const t0 = performance.now();
    window.spikeApi.handleA = mountCandidateA(rootA, blocks, { vimMode: opts.vimMode, virtualize: opts.virtualize });
    const mountMs = Number((performance.now() - t0).toFixed(2));
    return { mountMs, domNodes: rootA.querySelectorAll("*").length };
  },
  mountB(opts = {}) {
    window.spikeApi.handleB?.destroy();
    const blocks = opts.stressCount ? makeStressBlocks(opts.stressCount) : makeSampleBlocks();
    const t0 = performance.now();
    window.spikeApi.handleB = mountCandidateB(rootB, blocks, { vimMode: opts.vimMode });
    const mountMs = Number((performance.now() - t0).toFixed(2));
    return { mountMs, domNodes: rootB.querySelectorAll("*").length };
  },
};

// Mount default sample view for interactive inspection
window.spikeApi.mountA();
window.spikeApi.mountB();
