import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Button,
  TextField,
  MenuItem,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Typography,
  Alert,
  Snackbar,
} from "@mui/material";
import {
  Visibility as ViewIcon,
  Delete as DeleteIcon,
  Upload as UploadIcon,
} from "@mui/icons-material";
import { lettersApi, type LetterListItem } from "../api/client";

const typeColors: Record<string, "error" | "warning" | "info" | "default"> = {
  hacker: "error",
  compromise: "warning",
  vulnerability: "info",
  other: "default",
};

const typeLabels: Record<string, string> = {
  hacker: "Хакерская группировка",
  compromise: "Компрометация",
  vulnerability: "Уязвимости",
  other: "Прочее",
};

const statusLabels: Record<string, string> = {
  uploaded: "Загружен",
  parsed: "Текст извлечён",
  analyzed: "Проанализирован",
  assessed: "Оценён",
  completed: "Отчёт сформирован",
  failed: "Ошибка обработки",
  deleted: "Удалено",
};

export default function LetterList() {
  const navigate = useNavigate();
  const [letters, setLetters] = useState<LetterListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [filterType, setFilterType] = useState("");
  const [filterStatus, setFilterStatus] = useState("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);

  const PAGE_SIZE = 25;
  const [deleteIdState, setDeleteId] = useState<number | null>(null);
  const [deleting, setDeleting] = useState(false);

  const load = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const { data } = await lettersApi.list({
        letter_type: filterType || undefined,
        status: filterStatus || undefined,
        skip: page * PAGE_SIZE,
        limit: PAGE_SIZE,
      });
      setLetters(data);
      setError("");
    } catch (err: any) {
      setError(err.response?.data?.detail || (err as Error)?.message || "Не удалось загрузить письма");
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => { load(); }, [filterType, filterStatus, page]);

  useEffect(() => {
    const timer = window.setInterval(() => load(true), 5000);
    return () => window.clearInterval(timer);
  }, [filterType, filterStatus, page]);

  const filtered = letters.filter((l) => {
    if (search && !(l.letter_number || "").toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const handleDelete = async () => {
    if (deleteIdState === null) return;
    setDeleting(true);
    try {
      await lettersApi.delete(deleteIdState);
      setDeleteId(null);
      setNotice("Письмо удалено из списков (данные сохранены для аудита)");
      load();
    } catch (err: any) {
      setDeleteId(null);
      setError(err.response?.data?.detail || (err as Error)?.message || "Не удалось удалить письмо");
    } finally {
      setDeleting(false);
    }
  };

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
        <Typography variant="h5">Письма</Typography>
        <Button variant="contained" startIcon={<UploadIcon />} onClick={() => navigate("/upload")}>
          Загрузить письмо
        </Button>
      </Box>

      <Box sx={{ display: "flex", gap: 2, mb: 2 }}>
        <TextField
          size="small"
          label="Поиск по номеру"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          sx={{ width: 250 }}
        />
        <TextField
          size="small"
          select
          label="Тип"
          value={filterType}
          onChange={(e) => { setFilterType(e.target.value); setPage(0); }}
          sx={{ width: 200 }}
        >
          <MenuItem value="">Все</MenuItem>
          <MenuItem value="hacker">Хакерская группировка</MenuItem>
          <MenuItem value="compromise">Компрометация</MenuItem>
          <MenuItem value="vulnerability">Уязвимости</MenuItem>
          <MenuItem value="other">Прочее</MenuItem>
        </TextField>
        <TextField
          size="small"
          select
          label="Статус"
          value={filterStatus}
          onChange={(e) => { setFilterStatus(e.target.value); setPage(0); }}
          sx={{ width: 200 }}
        >
          <MenuItem value="">Все</MenuItem>
          <MenuItem value="uploaded">Загружен</MenuItem>
          <MenuItem value="parsed">Извлечён текст</MenuItem>
          <MenuItem value="analyzed">Проанализирован</MenuItem>
          <MenuItem value="assessed">Оценён</MenuItem>
          <MenuItem value="completed">Отчёт сформирован</MenuItem>
          <MenuItem value="failed">Ошибка обработки</MenuItem>
        </TextField>
        <Box sx={{ ml: "auto", display: "flex", alignItems: "center", gap: 1 }}>
          <Button size="small" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
            Назад
          </Button>
          <Typography variant="caption">стр. {page + 1}</Typography>
          <Button size="small" disabled={letters.length < PAGE_SIZE} onClick={() => setPage((p) => p + 1)}>
            Вперёд
          </Button>
        </Box>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError("")}>{error}</Alert>}
      <Snackbar open={Boolean(notice)} autoHideDuration={5000} onClose={() => setNotice("")}
                message={notice} anchorOrigin={{ vertical: "bottom", horizontal: "center" }} />

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
              <TableCell align="center">Действия</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filtered.length === 0 && !loading ? (
              <TableRow>
                <TableCell colSpan={9} align="center">
                  <Typography color="text.secondary" sx={{ py: 3 }}>
                    {letters.length === 0 ? "Нет писем. Загрузите первое письмо." : "Ничего не найдено"}
                  </Typography>
                </TableCell>
              </TableRow>
            ) : (
              filtered.map((letter) => (
                <TableRow key={letter.id} hover>
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
                    <Chip
                      label={statusLabels[letter.status] || letter.status}
                      size="small"
                      variant="outlined"
                    />
                  </TableCell>
                  <TableCell align="center">{letter.threat_count}</TableCell>
                  <TableCell align="center">{letter.ioc_count}</TableCell>
                  <TableCell align="center">{letter.vuln_count}</TableCell>
                  <TableCell>{new Date(letter.created_at).toLocaleDateString("ru-RU")}</TableCell>
                  <TableCell align="center">
                    <IconButton size="small" aria-label="Открыть письмо" onClick={() => navigate(`/letters/${letter.id}`)}>
                      <ViewIcon fontSize="small" />
                    </IconButton>
                    <IconButton size="small" aria-label="Удалить письмо" onClick={() => setDeleteId(letter.id)}>
                      <DeleteIcon fontSize="small" />
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog open={deleteIdState !== null} onClose={() => setDeleteId(null)}>
        <DialogTitle>Удалить письмо?</DialogTitle>
        <DialogContent>
          <Typography>
            Письмо будет скрыто из списков и статистики. Файлы и данные сохраняются
            для аудита (мягкое удаление).
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteId(null)}>Отмена</Button>
          <Button color="error" onClick={handleDelete} disabled={deleting}>Удалить</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
