import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box,
  Typography,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  Tabs,
  Tab,
  Alert,
  Chip,
  Snackbar,
  Tooltip,
} from "@mui/material";
import {
  Check as CheckIcon,
  Close as CloseIcon,
  OpenInNew as OpenInNewIcon,
} from "@mui/icons-material";
import { candidatesApi, type MeasureCandidate } from "../../api/client";

const STATUSES: Array<{ key: string; label: string }> = [
  { key: "pending", label: "На рассмотрении" },
  { key: "approved", label: "Утверждённые" },
  { key: "rejected", label: "Отклонённые" },
];

export default function Measures() {
  const navigate = useNavigate();
  const [status, setStatus] = useState("pending");
  const [items, setItems] = useState<MeasureCandidate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [snack, setSnack] = useState("");
  const [busy, setBusy] = useState<number | null>(null);

  const load = async (st: string) => {
    setLoading(true);
    setError("");
    try {
      const { data } = await candidatesApi.list(st);
      setItems(data);
    } catch (err: any) {
      setError(err.response?.data?.detail || (err as Error)?.message || "Ошибка загрузки");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(status); }, [status]);

  const decide = async (c: MeasureCandidate, action: "accept" | "reject") => {
    setBusy(c.id);
    setError("");
    try {
      if (action === "accept") {
        const r = await candidatesApi.accept(c.id);
        setSnack(r.data.measure_id ? "Мера утверждена и добавлена в библиотеку" : "Мера уже в библиотеке");
      } else {
        await candidatesApi.reject(c.id);
        setSnack("Мера отклонена");
      }
      await load(status);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Ошибка");
    } finally {
      setBusy(null);
    }
  };

  return (
    <Box>
      <Typography variant="h5" gutterBottom>Меры на рассмотрении</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Меры, добавленные LLM при генерации ответа. Администратор утверждает их в библиотеку
        мер либо отклоняет.
      </Typography>

      <Tabs value={status} onChange={(_, v) => setStatus(v)} sx={{ mb: 2 }}>
        {STATUSES.map((s) => <Tab key={s.key} label={s.label} value={s.key} />)}
      </Tabs>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <TableContainer component={Paper}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>ID</TableCell>
              <TableCell>Письмо</TableCell>
              <TableCell>Угроза</TableCell>
              <TableCell>Мера</TableCell>
              <TableCell>Примечание</TableCell>
              <TableCell>Статус</TableCell>
              <TableCell align="center">Действия</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading ? (
              <TableRow><TableCell colSpan={7} align="center">Загрузка...</TableCell></TableRow>
            ) : items.length === 0 ? (
              <TableRow><TableCell colSpan={7} align="center">Нет записей</TableCell></TableRow>
            ) : (
              items.map((c) => (
                <TableRow key={c.id} hover>
                  <TableCell>{c.id}</TableCell>
                  <TableCell>
                    {c.document_id ? (
                      <Tooltip title="Открыть письмо">
                        <Button
                          size="small"
                          endIcon={<OpenInNewIcon fontSize="small" />}
                          onClick={() => navigate(`/letters/${c.document_id}`)}
                        >
                          {c.letter_number || `№${c.document_id}`} {c.letter_date ? `от ${c.letter_date}` : ""}
                        </Button>
                      </Tooltip>
                    ) : "—"}
                  </TableCell>
                  <TableCell sx={{ maxWidth: 220 }}>{c.threat_theme || "—"}</TableCell>
                  <TableCell sx={{ maxWidth: 420 }}>{c.text}</TableCell>
                  <TableCell sx={{ maxWidth: 180, color: "text.secondary" }}>{c.note || "—"}</TableCell>
                  <TableCell>
                    <Chip
                      size="small"
                      label={STATUSES.find((s) => s.key === c.status)?.label || c.status}
                      color={c.status === "approved" ? "success" : c.status === "rejected" ? "error" : "warning"}
                    />
                  </TableCell>
                  <TableCell align="center">
                    {c.status === "pending" ? (
                      <Box sx={{ display: "flex", gap: 0.5, justifyContent: "center" }}>
                        <Button
                          size="small"
                          color="success"
                          variant="outlined"
                          startIcon={<CheckIcon />}
                          disabled={busy === c.id}
                          onClick={() => decide(c, "accept")}
                        >
                          Принять
                        </Button>
                        <Button
                          size="small"
                          color="error"
                          variant="outlined"
                          startIcon={<CloseIcon />}
                          disabled={busy === c.id}
                          onClick={() => decide(c, "reject")}
                        >
                          Отклонить
                        </Button>
                      </Box>
                    ) : "—"}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>

      <Snackbar open={Boolean(snack)} autoHideDuration={4000} onClose={() => setSnack("")}
        message={snack} anchorOrigin={{ vertical: "bottom", horizontal: "center" }} />
    </Box>
  );
}