import { useEffect, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Chip,
  MenuItem,
  Paper,
  Select,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { auditApi, lettersApi, type AuditItem, type StatsResponse } from "../api/client";

export default function Audit() {
  const [items, setItems] = useState<AuditItem[]>([]);
  const [total, setTotal] = useState(0);
  const [action, setAction] = useState("");
  const [documentId, setDocumentId] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState<StatsResponse | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const [{ data }, statsRes] = await Promise.all([
        auditApi.list({
          action: action || undefined,
          document_id: documentId ? Number(documentId) : undefined,
          limit: 300,
        }),
        lettersApi.stats({ mine: false }),
      ]);
      setItems(data.items);
      setStats(statsRes.data);
      setTotal(data.total);
      setError("");
    } catch (err: any) {
      setError(err.response?.data?.detail || "Не удалось загрузить журнал аудита");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  return (
    <Box>
      <Typography variant="h5" sx={{ mb: 2 }}>Журнал аудита</Typography>
      <Alert severity="info" sx={{ mb: 2 }}>
        Все действия пользователей: вход, загрузка, просмотр, скачивание, изменение данных и ошибки.
      </Alert>
      {stats && (
        <Paper sx={{ p: 2, mb: 2, display: "flex", gap: 3, flexWrap: "wrap" }}>
          <Typography><b>Всего писем:</b> {stats.total_letters}</Typography>
          <Typography><b>Угроз:</b> {stats.total_threats}</Typography>
          <Typography><b>IoC:</b> {stats.total_iocs}</Typography>
          <Typography><b>Уязвимостей:</b> {stats.total_vulns}</Typography>
        </Paper>
      )}
      <Paper sx={{ p: 2, mb: 2 }}>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", alignItems: "center" }}>
          <Select size="small" value={action} onChange={(e) => setAction(e.target.value)} displayEmpty sx={{ minWidth: 220 }}>
            <MenuItem value="">Все действия</MenuItem>
            {["login", "login_failed", "upload", "view_document", "download_report", "download_source",
              "generate_reply", "update_response", "update_vulnerability", "update_measures",
              "ioc_create", "ioc_update", "ioc_delete", "external_security_error"].map((a) => (
              <MenuItem key={a} value={a}>{a}</MenuItem>
            ))}
          </Select>
          <TextField size="small" label="ID документа" value={documentId}
                     onChange={(e) => setDocumentId(e.target.value)} sx={{ width: 140 }} />
          <Button variant="contained" onClick={load} disabled={loading}>
            {loading ? "Загрузка..." : "Применить"}
          </Button>
          <Chip label={`Всего: ${total}`} />
        </Box>
      </Paper>
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      <TableContainer component={Paper}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Время</TableCell>
              <TableCell>Пользователь</TableCell>
              <TableCell>Действие</TableCell>
              <TableCell>Объект</TableCell>
              <TableCell>Документ</TableCell>
              <TableCell>IP</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {items.map((r) => (
              <TableRow key={r.id} hover>
                <TableCell>{r.created_at ? new Date(r.created_at).toLocaleString("ru-RU") : ""}</TableCell>
                <TableCell>{r.username || "—"}</TableCell>
                <TableCell><Chip size="small" label={r.action} /></TableCell>
                <TableCell>{r.object_type}{r.filename ? `: ${r.filename}` : ""}</TableCell>
                <TableCell>{r.document_id ?? "—"}</TableCell>
                <TableCell>{r.ip_address || "—"}</TableCell>
              </TableRow>
            ))}
            {items.length === 0 && !loading && (
              <TableRow><TableCell colSpan={6}>Записей нет</TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}
