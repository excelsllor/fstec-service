import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Grid,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import {
  Cached as RefreshIcon,
  CloudQueue as QueueIcon,
  Dns as DbIcon,
  Memory as MemoryIcon,
  MonitorHeart as HeartIcon,
} from "@mui/icons-material";
import { diagnosticsApi, type DiagnosticsResponse } from "../api/client";

const POLL_MS = 4000;

const serviceNames: Record<string, string> = {
  gateway: "API Gateway",
  ingest: "Ingest / OCR",
  llm: "LLM Service",
  security: "Security",
  reporting: "Reporting",
  audit: "Audit",
  vllm: "vLLM",
};

type BusInfo = {
  backend?: string;
  total: number;
  topics: Array<{ topic: string; count: number; last_id: number }>;
  error?: string;
};

function shortError(value?: string): string {
  if (!value) return "—";
  if (value.includes("CERTIFICATE_VERIFY_FAILED")) return "TLS: сертификат не доверен";
  if (value.includes("KafkaConnectionError")) return "Kafka: диагностический клиент не подключён";
  if (value.includes("timed out") || value.includes("timeout")) return "таймаут";
  return value.length > 90 ? value.slice(0, 90) + "…" : value;
}

function fmtTime(value: number | null): string {
  return value ? new Date(value * 1000).toLocaleTimeString("ru-RU") : "—";
}

function ageText(value: number | null): string {
  if (value === null || value === undefined) return "—";
  if (value < 60) return `${value} с`;
  if (value < 3600) return `${Math.floor(value / 60)} мин`;
  return `${Math.floor(value / 3600)} ч`;
}

function StatusChip({ ok, label }: { ok: boolean; label: string }) {
  return <Chip size="small" label={label} color={ok ? "success" : "error"} variant={ok ? "filled" : "outlined"} />;
}

const cardSx = { height: "100%", borderRadius: 2 };

export default function Diagnostics() {
  const [data, setData] = useState<DiagnosticsResponse | null>(null);
  const [bus, setBus] = useState<BusInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const [diagnostics, busResponse] = await Promise.all([
        diagnosticsApi.get(),
        diagnosticsApi.bus().catch(() => ({ data: { total: 0, topics: [], error: "нет связи с шиной" } })),
      ]);
      setData(diagnostics.data);
      setBus(busResponse.data);
      setUpdatedAt(new Date());
      setError("");
    } catch (err: any) {
      setError(err.response?.data?.detail || (err as Error)?.message || "Не удалось получить состояние сервисов");
    } finally {
      if (!silent) setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(() => load(true), POLL_MS);
    return () => clearInterval(timer);
  }, [load]);

  const db = data?.db;
  const llm = data?.llm;
  const services = data?.services || [];
  const aliveCount = services.filter((s) => s.alive).length;

  if (loading && !data) {
    return (
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, p: 4 }}>
        <CircularProgress size={28} />
        <Typography>Загружаем состояние сервисов…</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ width: "100%", maxWidth: "none" }}>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2, gap: 2, flexWrap: "wrap" }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>Отладка</Typography>
          <Typography variant="body2" color="text.secondary">
            Живое состояние сервисов, БД и внешних подключений
          </Typography>
        </Box>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          {updatedAt && (
            <Typography variant="caption" color="text.secondary">
              Обновлено: {updatedAt.toLocaleTimeString("ru-RU")}
            </Typography>
          )}
          <Button size="small" variant="outlined" startIcon={<RefreshIcon />} onClick={() => load()}>
            Обновить
          </Button>
        </Box>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      {data && (
        <>
          <Grid container spacing={2} sx={{ mb: 2 }}>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <Card sx={cardSx}>
                <CardContent>
                  <Typography variant="body2" color="text.secondary">Сервисы</Typography>
                  <Typography variant="h5" sx={{ mt: 0.5 }}>{aliveCount} / {services.length}</Typography>
                  <StatusChip ok={aliveCount === services.length} label={aliveCount === services.length ? "Все работают" : "Есть проблемы"} />
                </CardContent>
              </Card>
            </Grid>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <Card sx={cardSx}>
                <CardContent>
                  <Typography variant="body2" color="text.secondary">База данных</Typography>
                  <Typography variant="h5" sx={{ mt: 0.5 }}>{db?.reachable ? "Работает" : "Недоступна"}</Typography>
                  <Typography variant="caption" color="text.secondary">Пинг: {db?.latency_ms ?? "—"} мс</Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <Card sx={cardSx}>
                <CardContent>
                  <Typography variant="body2" color="text.secondary">LLM</Typography>
                  <Typography variant="h5" sx={{ mt: 0.5 }}>{llm?.reachable ? "Доступна" : "Недоступна"}</Typography>
                  <Typography variant="caption" color="text.secondary">{llm?.model || "—"} · пинг: {llm?.latency_ms ?? "—"} мс</Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <Card sx={cardSx}>
                <CardContent>
                  <Box sx={{ display: "flex", justifyContent: "space-between" }}>
                    <Box>
                      <Typography variant="body2" color="text.secondary">CPU / RAM</Typography>
                      <Typography variant="h5" sx={{ mt: 0.5 }}>{data.system.cpu_percent}%</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {data.system.memory_mb} МБ · диск {data.system.disk_free_gb} ГБ
                      </Typography>
                    </Box>
                    <MemoryIcon color="primary" />
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          <Grid container spacing={2}>
            <Grid size={{ xs: 12, lg: 8 }}>
              <Paper sx={{ p: 2, mb: 2, borderRadius: 2 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                  <HeartIcon color="primary" />
                  <Typography variant="h6">Сервисы</Typography>
                  <Chip size="small" label={`${aliveCount}/${services.length}`} />
                </Box>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Сервис</TableCell>
                        <TableCell>Статус</TableCell>
                        <TableCell>Пинг</TableCell>
                        <TableCell>PID</TableCell>
                        <TableCell>Последний пинг</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {services.map((s) => {
                        const ok = s.alive && (s.heartbeat_age_sec ?? Infinity) <= 60;
                        return (
                          <TableRow key={s.name} hover>
                            <TableCell sx={{ fontWeight: 600 }}>{serviceNames[s.name] || s.name}</TableCell>
                            <TableCell><StatusChip ok={ok} label={ok ? "OK" : "Нет ответа"} /></TableCell>
                            <TableCell>{ageText(s.heartbeat_age_sec)}</TableCell>
                            <TableCell>{s.pid ?? "—"}</TableCell>
                            <TableCell>{fmtTime(s.last_seen)}</TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2, borderRadius: 2 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                  <QueueIcon color="primary" />
                  <Typography variant="h6">Очередь сообщений</Typography>
                  {bus?.backend && <Chip size="small" variant="outlined" label={bus.backend.toUpperCase()} />}
                </Box>
                {bus?.error ? (
                  <Alert severity="warning" sx={{ mb: 1 }}>
                    {shortError(bus.error)}
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5 }}>
                      Шина событий Kafka работает в сервисах; диагностический клиент не прошёл SASL/TLS-настройки.
                    </Typography>
                  </Alert>
                ) : null}
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Топик</TableCell>
                      <TableCell>Сообщений</TableCell>
                      <TableCell>Последний offset</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {(bus?.topics || []).map((t) => (
                      <TableRow key={t.topic}>
                        <TableCell>{t.topic}</TableCell>
                        <TableCell>{t.count}</TableCell>
                        <TableCell>{t.last_id}</TableCell>
                      </TableRow>
                    ))}
                    {!bus?.topics?.length && (
                      <TableRow><TableCell colSpan={3}>Нет данных</TableCell></TableRow>
                    )}
                  </TableBody>
                </Table>
              </Paper>
            </Grid>

            <Grid size={{ xs: 12, lg: 4 }}>
              <Paper sx={{ p: 2, mb: 2, borderRadius: 2 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                  <DbIcon color="primary" />
                  <Typography variant="h6">База данных</Typography>
                </Box>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                  <StatusChip ok={!!db?.reachable} label={db?.reachable ? "Работает" : "Недоступна"} />
                  <Typography variant="body2" color="text.secondary">Пинг: {db?.latency_ms ?? "—"} мс</Typography>
                </Box>
                {db?.error && <Typography variant="caption" color="error">{shortError(db.error)}</Typography>}
              </Paper>

              <Paper sx={{ p: 2, mb: 2, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ mb: 1 }}>Внешние подключения</Typography>
                <Table size="small">
                  <TableBody>
                    {data.external.map((e) => (
                      <TableRow key={e.name}>
                        <TableCell>{e.name}</TableCell>
                        <TableCell>
                          <StatusChip ok={e.reachable} label={e.reachable ? "OK" : "Нет"} />
                        </TableCell>
                        <TableCell align="right">
                          {e.reachable ? `${e.latency_ms} мс` : shortError(e.error)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </Paper>

              <Paper sx={{ p: 2, mb: 2, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ mb: 1 }}>LLM</Typography>
                <Box sx={{ display: "flex", gap: 1, alignItems: "center", mb: 1 }}>
                  <StatusChip ok={!!llm?.reachable} label={llm?.reachable ? "Доступна" : "Нет связи"} />
                  <Chip size="small" variant="outlined" label={llm?.provider || "—"} />
                </Box>
                <Typography variant="body2">{llm?.model || "—"}</Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                  Пинг: {llm?.latency_ms ?? "—"} мс · {llm?.base_url || "—"}
                </Typography>
                {llm?.error && <Typography variant="caption" color="error">{shortError(llm.error)}</Typography>}
              </Paper>

              <Paper sx={{ p: 2, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ mb: 1 }}>Ресурсы узла</Typography>
                <Grid container spacing={1}>
                  <Grid size={6}><Typography variant="caption">CPU</Typography><Typography variant="h6">{data.system.cpu_percent}%</Typography></Grid>
                  <Grid size={6}><Typography variant="caption">RAM</Typography><Typography variant="h6">{data.system.memory_mb} МБ</Typography></Grid>
                  <Grid size={6}><Typography variant="caption">Диск свободно</Typography><Typography variant="h6">{data.system.disk_free_gb} ГБ</Typography></Grid>
                  <Grid size={6}><Typography variant="caption">Gateway RAM</Typography><Typography variant="h6">{data.system.gateway_proc_memory_mb} МБ</Typography></Grid>
                </Grid>
              </Paper>
            </Grid>
          </Grid>
        </>
      )}
    </Box>
  );
}
