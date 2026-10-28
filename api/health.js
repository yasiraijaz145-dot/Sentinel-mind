export default function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.status(200).json({
    service: "sentinelmind-dashboard-api",
    status: "ok",
    mode: "frontend-only",
    note: "Configure a separate Linux collector for real telemetry. This serverless function does not run Zeek, Suricata, Cowrie, or ML models."
  });
}
