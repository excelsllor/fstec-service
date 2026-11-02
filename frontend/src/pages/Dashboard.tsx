import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box,
  Grid,
  Paper,
  Typography,
  Card,
  CardContent,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Alert,
} from "@mui/material";
import {
  Mail as MailIcon,
  Warning as WarningIcon,
  BugReport as BugIcon,
  Shield as ShieldIcon,
  Upload as UploadIcon,
} from "@mui/icons-material";
import { lettersApi, type StatsResponse, type LetterListItem } from "../api/client";

const typeLabels: Record<string, string> = {
  hacker: "Хакерская группировка",
  compromise: "Компрометация",
  vulnerability: "Уязвимости",
  other: "Прочее",
};

const typeColors: Record<string, "error" | "warning" | "info" | "default"> = {
  hacker: "error",
  compromise: "warning",
  vulnerability: "info",
  other: "default",
};

const statusLabels: Record<string, string> = {
  uploaded: "Загружен",
  parsed: "Текст извлечён",
  analyzed: "Проанализирован",
  assessed: "Оценён",
  completed: "Отчёт сформирован",
  failed: "Ошибка обработки",
};

export default function Dashboard() {
  const navigate = useNavigate();
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [letters, setLetters] = useState<LetterListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const loadData = async () => {
      try {
        const [statsRes, lettersRes] = await Promise.all([lettersApi.stats({ mine: true }), lettersApi.list({ mine: true })]);
        setStats(statsRes.data);
        setLetters(lettersRes.data);
        setError("");
      } catch (err: any) {
        setError(err.response?.data?.detail || (err as Error)?.message || "Не удалось загрузить панель");
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, []);

  const statCards = [
    { label: "Всего писем", value: stats?.total_letters ?? 0, icon: <MailIcon />, color: "#1976d2" },
    { label: "Угроз", value: stats?.total_threats ?? 0, icon: <WarningIcon />, color: "#d32f2f" },
    { label: "IOC", value: stats?.total_iocs ?? 0, icon: <ShieldIcon />, color: "#388e3c" },
    { label: "Уязвимостей", value: stats?.total_vulns ?? 0, icon: <BugIcon />, color: "#f57c00" },
  ];

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Typography variant="h5">Панель управления</Typography>
        <Button variant="contained" startIcon={<UploadIcon />} onClick={() => navigate("/upload")}>
          Загрузить письмо
        </Button>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Grid container spacing={2} sx={{ mb: 3 }}>
        {statCards.map((card) => (
          <Grid size={{ xs: 12, sm: 6, md: 3 }} key={card.label}>
            <Card>
              <CardContent>
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <Box>
                    <Typography color="text.secondary" variant="body2">{card.label}</Typography>
                    <Typography variant="h4" sx={{ mt: 1 }}>{loading ? "—" : card.value}</Typography>
                  </Box>
                  <Box sx={{ color: card.color, "& svg": { fontSize: 40 } }}>{card.icon}</Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Typography variant="h6" gutterBottom>Последние письма</Typography>
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>№</TableCell>
              <TableCell>Дата</TableCell>
              <TableCell>Тип</TableCell>
              <TableCell>Статус</TableCell>
              <TableCell align="center">Угроз</TableCell>
              <TableCell align="center">IOC</TableCell>
              <TableCell align="center">Уязв.</TableCell>
              <TableCell>Создано</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {letters.length === 0 && !loading ? (
              <TableRow>
                <TableCell colSpan={8} align="center">
                  <Typography color="text.secondary" sx={{ py: 3 }}>
                    Нет писем. <Button onClick={() => navigate("/upload")}>Загрузите первое</Button>
                  </Typography>
                </TableCell>
              </TableRow>
            ) : (
              letters.slice(0, 10).map((letter) => (
                <TableRow key={letter.id} hover sx={{ cursor: "pointer" }} onClick={() => navigate(`/letters/${letter.id}`)}>
                  <TableCell>{letter.letter_number || "—"}</TableCell>
                  <TableCell>{letter.letter_date || "—"}</TableCell>
                  <TableCell>
                    <Chip
                      label={typeLabels[letter.letter_type] || letter.letter_type}
                      color={typeColors[letter.letter_type] || "default"}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <Chip label={statusLabels[letter.status] || letter.status} size="small" variant="outlined" />
                  </TableCell>
                  <TableCell align="center">{letter.threat_count}</TableCell>
                  <TableCell align="center">{letter.ioc_count}</TableCell>
                  <TableCell align="center">{letter.vuln_count}</TableCell>
                  <TableCell>{new Date(letter.created_at).toLocaleDateString("ru-RU")}</TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}
