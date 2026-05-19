interface Props {
  label: string;
}

const STYLES: Record<string, string> = {
  critical: "bg-severity-critical text-white",
  high: "bg-severity-high text-white",
  medium: "bg-severity-medium text-white",
  low: "bg-severity-low text-white",
  info: "bg-severity-info text-white",
};

export default function SeverityBadge({ label }: Props) {
  const style = STYLES[label] ?? "bg-slate-200 text-slate-700";
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded text-xs font-semibold tracking-wide uppercase ${style}`}
    >
      {label}
    </span>
  );
}
