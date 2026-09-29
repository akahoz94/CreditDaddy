/**
 * Qoder 客户端探测：0.3+ 启动器把实际运行的版本放在 .qoder-versions\<ver>\resources，
 * 顶层 resources 可能是旧版残留或根本没有。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const qa = await import('../src/qoderApp.js');

function touch(file, content = '') {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
}

function withFakeWindowsDirs(fn) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qoder-detect-'));
  const keys = ['LOCALAPPDATA', 'ProgramFiles', 'ProgramFiles(x86)', 'APPDATA'];
  const prev = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  process.env.LOCALAPPDATA = path.join(root, 'Local');
  process.env.ProgramFiles = path.join(root, 'PF');
  process.env['ProgramFiles(x86)'] = path.join(root, 'PF86');
  process.env.APPDATA = path.join(root, 'Roaming');
  try { return fn(root); } finally {
    for (const k of keys) { if (prev[k] === undefined) delete process.env[k]; else process.env[k] = prev[k]; }
    fs.rmSync(root, { recursive: true, force: true });
  }
}

const manifest = (v) => JSON.stringify({ productVersion: v });

test('新版安装布局：只有 .qoder-versions，取最高版本的 runtime-info', { skip: process.platform !== 'win32' }, () => {
  withFakeWindowsDirs((root) => {
    const inst = path.join(root, 'Local', 'Programs', 'Qoder', '.qoder-versions');
    for (const v of ['0.3.4', '0.10.0', '0.4.1']) {
      touch(path.join(inst, v, 'resources', 'umid', 'runtime-info.exe'));
      touch(path.join(inst, v, 'resources', 'build-manifest.json'), manifest(v));
    }
    const intl = qa.detectQoderApps().find((a) => a.provider === 'qoder');
    assert.equal(intl.installed, true);
    assert.equal(intl.version, '0.10.0', '按数值比较版本，不是字符串序');
    assert.ok(intl.runtimeInfo.includes(path.join('0.10.0', 'resources', 'umid')));
  });
});

test('顶层 resources 是旧版残留且没有 runtime-info 时，改用版本目录', { skip: process.platform !== 'win32' }, () => {
  withFakeWindowsDirs((root) => {
    const inst = path.join(root, 'PF', 'Qoder');
    touch(path.join(inst, 'resources', 'build-manifest.json'), manifest('0.2.5'));
    touch(path.join(inst, '.qoder-versions', '0.4.1', 'resources', 'umid', 'runtime-info.exe'));
    touch(path.join(inst, '.qoder-versions', '0.4.1', 'resources', 'build-manifest.json'), manifest('0.4.1'));
    const intl = qa.detectQoderApps().find((a) => a.provider === 'qoder');
    assert.equal(intl.version, '0.4.1');
    assert.ok(intl.runtimeInfo, '应检测到 runtime-info');
  });
});

test('国际版目录不会被当成国内版（Qoder vs Qoder CN）', { skip: process.platform !== 'win32' }, () => {
  withFakeWindowsDirs((root) => {
    touch(path.join(root, 'Local', 'Programs', 'Qoder CN', '.qoder-versions', '0.4.1', 'resources', 'umid', 'runtime-info.exe'));
    touch(path.join(root, 'Local', 'Programs', 'Qoder', '.qoder-versions', '0.4.1', 'resources', 'umid', 'runtime-info.exe'));
    const [intl, cn] = ['qoder', 'qoder-cn'].map((p) => qa.detectQoderApps().find((a) => a.provider === p));
    assert.ok(intl.runtimeInfo.includes(`${path.sep}Qoder${path.sep}`));
    assert.ok(cn.runtimeInfo.includes(`${path.sep}Qoder CN${path.sep}`));
  });
});
