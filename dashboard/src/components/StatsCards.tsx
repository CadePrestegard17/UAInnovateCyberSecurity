import clsx from 'clsx';
import type { ReactNode } from 'react';

type CardProps = {
  title: string;
  value: string | number;
  subtitle?: string;
  className?: string;
};

export function StatCard({ title, value, subtitle, className }: CardProps) {
  return (
    <div className={clsx('stat-card', className)}>
      <div className="stat-card__title">{title}</div>
      <div className="stat-card__value">{value}</div>
      {subtitle != null && <div className="stat-card__subtitle">{subtitle}</div>}
    </div>
  );
}

export function StatsCards({ children }: { children: ReactNode }) {
  return <div className="stats-cards">{children}</div>;
}
