import { Navigate, Route, Routes } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import TopBar from './components/TopBar';
import { ToastHost } from './components/toast';
import BrowsePage from './pages/BrowsePage';
import ReportPage from './pages/ReportPage';
import HistoryPage from './pages/HistoryPage';
import LivePage from './pages/LivePage';
import KbPage from './pages/KbPage';
import SettingsPage from './pages/SettingsPage';

export default function App() {
  return (
    <div className="app-shell">
      <Sidebar />
      <div className="app-main">
        <TopBar />
        <div className="app-content">
          <Routes>
            <Route path="/" element={<Navigate to="/browse" replace />} />
            <Route path="/browse" element={<BrowsePage />} />
            <Route path="/report" element={<ReportPage />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="/live" element={<LivePage />} />
            <Route path="/kb" element={<KbPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/browse" replace />} />
          </Routes>
        </div>
      </div>
      <ToastHost />
    </div>
  );
}
