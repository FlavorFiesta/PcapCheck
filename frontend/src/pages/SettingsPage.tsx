// 设置页:tshark 路径 / LLM / 脱敏 / 知识库目录(GET/PUT /api/settings)
import { useEffect, useState } from 'react';
import { api } from '../api/endpoints';
import type { AppSettings } from '../api/types';
import { toastApiError, toastSuccess } from '../components/toast';

export default function SettingsPage() {
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testMessage, setTestMessage] = useState<string | null>(null);

  useEffect(() => {
    api
      .getSettings()
      .then((s) => setSettings(s !== null && typeof s === 'object' ? (s as AppSettings) : {}))
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  if (error) {
    return (
      <div className="page">
        <div className="err-text">加载设置失败:{error}</div>
      </div>
    );
  }
  if (!settings) {
    return (
      <div className="page dim">
        加载中…
      </div>
    );
  }

  const update = (patch: Partial<AppSettings>) => setSettings((s) => (s ? { ...s, ...patch } : s));

  const save = async () => {
    if (!settings) return;
    setSaving(true);
    try {
      const r = await api.putSettings(settings);
      setSettings(r);
      toastSuccess('设置已保存');
    } catch (e) {
      toastApiError(e, '保存失败');
    } finally {
      setSaving(false);
    }
  };

  const testLlm = async () => {
    if (!settings) return;
    setTesting(true);
    setTestMessage(null);
    try {
      const r = await api.testLlm(settings);
      setTestMessage(`连接成功：${r.reply ?? '模型已响应'}`);
    } catch (e) {
      setTestMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="page settings-page">
      <h2>设置</h2>

      <section>
        <h3>引擎</h3>
        <label className="field">
          <span>tshark 路径</span>
          <input
            value={settings.tshark_path ?? ''}
            onChange={(e) => update({ tshark_path: e.target.value })}
            placeholder="例如 C:\Program Files\Wireshark\tshark.exe"
          />
        </label>
      </section>

      <section>
        <h3>LLM(OpenAI 兼容协议)</h3>
        <label className="field switch">
          <input
            type="checkbox"
            checked={!!settings.llm?.enabled}
            onChange={(e) => update({ llm: { ...settings.llm, enabled: e.target.checked } })}
          />
          <span>启用 AI 辅助诊断分析(可选,不改变规则结论)</span>
        </label>
        <label className="field">
          <span>Base URL</span>
          <input
            value={settings.llm?.base_url ?? ''}
            onChange={(e) => update({ llm: { ...settings.llm, base_url: e.target.value } })}
            placeholder="https://api.example.com/v1"
          />
        </label>
        <label className="field">
          <span>API Key</span>
          <input
            type="password"
            value={settings.llm?.api_key ?? ''}
            onChange={(e) => update({ llm: { ...settings.llm, api_key: e.target.value } })}
            placeholder="sk-..."
          />
        </label>
        <label className="field">
          <span>模型</span>
          <input
            value={settings.llm?.model ?? ''}
            onChange={(e) => update({ llm: { ...settings.llm, model: e.target.value } })}
            placeholder="gpt-4o-mini / deepseek-chat / ..."
          />
        </label>
        <div className="form-actions">
          <button className="btn" disabled={testing} onClick={() => void testLlm()}>
            {testing ? '测试中…' : '测试 API 连接'}
          </button>
          {testMessage && <span className="dim">{testMessage}</span>}
        </div>
      </section>

      <section>
        <h3>脱敏</h3>
        <label className="field switch">
          <input
            type="checkbox"
            checked={!!settings.masking?.enabled}
            onChange={(e) => update({ masking: { enabled: e.target.checked } })}
          />
          <span>分析前对 IP / 域名脱敏(推荐开启,可关)</span>
        </label>
      </section>

      <section>
        <h3>知识库</h3>
        <label className="field">
          <span>知识库目录</span>
          <input
            value={settings.kb_dir ?? ''}
            onChange={(e) => update({ kb_dir: e.target.value })}
            placeholder="后端本机的 Markdown 目录"
          />
        </label>
      </section>

      <div className="form-actions">
        <button className="btn primary" disabled={saving} onClick={() => void save()}>
          {saving ? '保存中…' : '保存设置'}
        </button>
      </div>
    </div>
  );
}
