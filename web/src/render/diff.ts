export type DiffLineKind = "context" | "add" | "del";

export interface DiffLine {
  kind: DiffLineKind;
  oldLine: number | null;
  newLine: number | null;
  text: string;
}

const MAX_LCS_LINES = 2000;
const MAX_LCS_CELLS = 4_000_000;

function splitLines(text: string): string[] {
  if (text.length === 0) {
    return [];
  }
  return text.replace(/\r\n/g, "\n").split("\n");
}

export function computeLineDiff(oldText: string, newText: string): DiffLine[] {
  const oldLines = splitLines(oldText);
  const newLines = splitLines(newText);

  if (oldLines.length === 0 && newLines.length === 0) {
    return [];
  }

  let prefixLen = 0;
  const minLen = Math.min(oldLines.length, newLines.length);
  while (prefixLen < minLen && oldLines[prefixLen] === newLines[prefixLen]) {
    prefixLen += 1;
  }

  let suffixLen = 0;
  while (
    suffixLen < oldLines.length - prefixLen &&
    suffixLen < newLines.length - prefixLen &&
    oldLines[oldLines.length - 1 - suffixLen] === newLines[newLines.length - 1 - suffixLen]
  ) {
    suffixLen += 1;
  }

  const result: DiffLine[] = [];

  for (let i = 0; i < prefixLen; i += 1) {
    result.push({
      kind: "context",
      oldLine: i + 1,
      newLine: i + 1,
      text: oldLines[i],
    });
  }

  const oldMidStart = prefixLen;
  const oldMidEnd = oldLines.length - suffixLen;
  const newMidStart = prefixLen;
  const newMidEnd = newLines.length - suffixLen;
  const m = oldMidEnd - oldMidStart;
  const n = newMidEnd - newMidStart;

  if (m === 0 && n > 0) {
    for (let j = 0; j < n; j += 1) {
      result.push({
        kind: "add",
        oldLine: null,
        newLine: newMidStart + j + 1,
        text: newLines[newMidStart + j],
      });
    }
  } else if (n === 0 && m > 0) {
    for (let i = 0; i < m; i += 1) {
      result.push({
        kind: "del",
        oldLine: oldMidStart + i + 1,
        newLine: null,
        text: oldLines[oldMidStart + i],
      });
    }
  } else if (m > 0 && n > 0) {
    if (m <= MAX_LCS_LINES && n <= MAX_LCS_LINES && m * n <= MAX_LCS_CELLS) {
      const stride = n + 1;
      const dp = new Uint32Array((m + 1) * stride);

      for (let i = m - 1; i >= 0; i -= 1) {
        const oldLine = oldLines[oldMidStart + i];
        const rowOffset = i * stride;
        const nextRowOffset = (i + 1) * stride;
        for (let j = n - 1; j >= 0; j -= 1) {
          if (oldLine === newLines[newMidStart + j]) {
            dp[rowOffset + j] = dp[nextRowOffset + j + 1] + 1;
          } else {
            const down = dp[nextRowOffset + j];
            const right = dp[rowOffset + j + 1];
            dp[rowOffset + j] = down >= right ? down : right;
          }
        }
      }

      let i = 0;
      let j = 0;
      while (i < m && j < n) {
        const oldIdx = oldMidStart + i;
        const newIdx = newMidStart + j;
        if (oldLines[oldIdx] === newLines[newIdx]) {
          result.push({
            kind: "context",
            oldLine: oldIdx + 1,
            newLine: newIdx + 1,
            text: oldLines[oldIdx],
          });
          i += 1;
          j += 1;
        } else if (dp[(i + 1) * stride + j] >= dp[i * stride + j + 1]) {
          result.push({
            kind: "del",
            oldLine: oldIdx + 1,
            newLine: null,
            text: oldLines[oldIdx],
          });
          i += 1;
        } else {
          result.push({
            kind: "add",
            oldLine: null,
            newLine: newIdx + 1,
            text: newLines[newIdx],
          });
          j += 1;
        }
      }

      while (i < m) {
        const oldIdx = oldMidStart + i;
        result.push({
          kind: "del",
          oldLine: oldIdx + 1,
          newLine: null,
          text: oldLines[oldIdx],
        });
        i += 1;
      }

      while (j < n) {
        const newIdx = newMidStart + j;
        result.push({
          kind: "add",
          oldLine: null,
          newLine: newIdx + 1,
          text: newLines[newIdx],
        });
        j += 1;
      }
    } else {
      for (let i = 0; i < m; i += 1) {
        result.push({
          kind: "del",
          oldLine: oldMidStart + i + 1,
          newLine: null,
          text: oldLines[oldMidStart + i],
        });
      }
      for (let j = 0; j < n; j += 1) {
        result.push({
          kind: "add",
          oldLine: null,
          newLine: newMidStart + j + 1,
          text: newLines[newMidStart + j],
        });
      }
    }
  }

  for (let s = 0; s < suffixLen; s += 1) {
    const oldIdx = oldLines.length - suffixLen + s;
    const newIdx = newLines.length - suffixLen + s;
    result.push({
      kind: "context",
      oldLine: oldIdx + 1,
      newLine: newIdx + 1,
      text: oldLines[oldIdx],
    });
  }

  return result;
}
