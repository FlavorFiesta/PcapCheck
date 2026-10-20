// 顶层错误边界:任何未捕获的渲染异常都以中文错误卡片呈现,绝不允许黑屏。
import { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
  info: string;
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, info: '' };

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // React 18 的渲染期异常会被吞掉并卸载整树,这里显式留下诊断信息
    console.error('[报文快速分析工具] 未捕获的渲染异常:', error, info.componentStack);
    this.setState({ info: info.componentStack ?? '' });
  }

  render() {
    const { error, info } = this.state;
    if (!error) return this.props.children;
    return (
      <div className="error-boundary">
        <div className="eb-card">
          <h2>界面出现未捕获的渲染异常</h2>
          <div className="eb-msg">{error.message || String(error)}</div>
          {error.stack && <pre className="eb-stack">{error.stack.slice(0, 2000)}</pre>}
          {info && <pre className="eb-stack">{info.slice(0, 1200)}</pre>}
          <p className="dim">点击「重试」将重新挂载界面;若反复出现,请刷新页面,并把上方信息反馈给开发。</p>
          <div className="eb-actions">
            <button className="btn primary" onClick={() => this.setState({ error: null, info: '' })}>
              重试
            </button>
            <button className="btn" onClick={() => window.location.reload()}>
              刷新页面
            </button>
          </div>
        </div>
      </div>
    );
  }
}
