export function JsonPanel({ value, label = "Raw JSON" }: { value: unknown; label?: string }) {
  return (
    <details className="raw">
      <summary>{label}</summary>
      <div>
        <pre>{JSON.stringify(value, null, 2)}</pre>
      </div>
    </details>
  );
}
