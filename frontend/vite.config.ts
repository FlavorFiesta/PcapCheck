import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// 后端 FastAPI 固定 8123(本机 8000 在 Windows 保留端口段内,绑定报 10013);
// 开发期 /api 与 /ws 全部代理过去;生产模式由后端直接托管 dist
export default defineConfig({
  plugins: [react()],
  build: {
    // echarts 完整包约 1MB,内部工具可接受
    chunkSizeWarningLimit: 1200,
    rollupOptions: {
      output: {
        manualChunks: {
          echarts: ['echarts', 'echarts-for-react'],
          react: ['react', 'react-dom', 'react-router-dom'],
        },
      },
    },
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': 'http://127.0.0.1:8123',
      '/ws': { target: 'ws://127.0.0.1:8123', ws: true },
    },
  },
});
