/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** 设为 "1" 时启用前端开发 mock(默认关闭) */
  readonly VITE_MOCK?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
