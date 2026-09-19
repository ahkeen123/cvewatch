export default function AdminSettings() {
  return (
    <div>
      <h1 className="mb-1 text-2xl font-semibold">Admin settings</h1>
      <p className="mb-6 text-sm text-console-muted">
        These values are configured via environment variables on the server, not in this UI, so a
        misconfigured key can't be changed by a viewer session.
      </p>

      <div className="max-w-2xl overflow-hidden rounded border border-console-border">
        <SettingRow name="NVD_API_KEY" description="Raises the NVD rate limit from 5 to 50 requests/30s. Optional." />
        <SettingRow
          name="AI_PROVIDER"
          description={'Set to "anthropic" or "openai" to enable real fix summaries; defaults to "stub".'}
        />
        <SettingRow name="ANTHROPIC_API_KEY" description="Required if AI_PROVIDER=anthropic." />
        <SettingRow name="OPENAI_API_KEY" description="Required if AI_PROVIDER=openai." />
        <SettingRow name="JWT_SECRET" description="Signs login sessions. Rotate this to invalidate all sessions." />
      </div>

      <p className="mt-6 text-sm text-console-muted">
        See <code className="rounded bg-console-panel px-1.5 py-0.5 font-mono text-xs">.env.example</code> in the
        project root for the full list and setup instructions.
      </p>
    </div>
  );
}

function SettingRow({ name, description }: { name: string; description: string }) {
  return (
    <div className="border-b border-console-border bg-console-panel px-4 py-3 last:border-b-0">
      <div className="font-mono text-sm text-console-signal">{name}</div>
      <div className="text-sm text-console-muted">{description}</div>
    </div>
  );
}
