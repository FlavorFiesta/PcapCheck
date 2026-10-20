import { NavLink } from 'react-router-dom';

const NAV = [
  { to: '/report', label: '一键分析' },
  { to: '/history', label: '历史' },
  { to: '/live', label: '实时抓包' },
  { to: '/kb', label: '知识库' },
  { to: '/settings', label: '设置' },
];

export default function Sidebar() {
  return (
    <nav className="sidebar">
      <div className="brand">
        报文检查
      </div>
      {NAV.map((n) => (
        <NavLink key={n.to} to={n.to} className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}>
          {n.label}
        </NavLink>
      ))}
      <div className="sidebar-foot">报文检查 v1.0.8</div>
    </nav>
  );
}
