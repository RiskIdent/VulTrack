import { ReactNode } from 'react';
import { clsx } from 'clsx';

interface StatCardProps {
  title: string;
  value: number | string;
  icon: ReactNode;
  trend?: {
    value: number;
    label: string;
  };
  variant?: 'default' | 'critical' | 'high' | 'success';
  className?: string;
}

export default function StatCard({ title, value, icon, trend, variant = 'default', className }: StatCardProps) {
  const variants = {
    default: 'border-[#2d3f36]',
    critical: 'border-red-600/50 bg-red-600/5',
    high: 'border-orange-600/50 bg-orange-600/5',
    success: 'border-green-600/50 bg-green-600/5',
  };

  return (
    <div className={clsx('card', variants[variant], className)}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-[#a5d6a7] mb-1">{title}</p>
          <p className="text-3xl font-bold text-[#e8f5e9]">{value}</p>
          {trend && (
            <p className={clsx(
              'text-xs mt-2',
              trend.value >= 0 ? 'text-red-400' : 'text-green-400'
            )}>
              {trend.value >= 0 ? '+' : ''}{trend.value} {trend.label}
            </p>
          )}
        </div>
        <div className="w-12 h-12 bg-[#1a2420] rounded-lg flex items-center justify-center">
          {icon}
        </div>
      </div>
    </div>
  );
}
