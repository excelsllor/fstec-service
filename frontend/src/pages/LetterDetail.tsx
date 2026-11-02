import { useEffect, useState, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  Box,
  Typography,
  Tabs,
  Tab,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Button,
  Alert,
  IconButton,
  Grid,
  Card,
  CardContent,
  Snackbar,
  FormControl,
  Select,
  MenuItem,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  TextField,
  Divider,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  LinearProgress,
} from "@mui/material";
import {
  ArrowBack as BackIcon,
  Download as DownloadIcon,
  Refresh as RefreshIcon,
  ContentCopy as CopyIcon,
  ExpandMore as ExpandMoreIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  AutoFixHigh as AutoFixHighIcon,
} from "@mui/icons-material";
import {
  lettersApi,
  documentsApi,
  type LetterResponse,
  type IoCResponse,
  type ThreatResponse,
  type VulnerabilityResponse,
} from "../api/client";

const iocTypeLabels: Record<string, string> = {
  ip_cidr: "IP CIDR",
  ipv6: "IPv6",
  url: "URL",
  ip: "IP-адрес",
  domain: "Домен",
  hash: "Хэш",
  email: "Email",
  bdu: "BDU",
  cve: "CVE",
};

const iocChipColors: Record<string, "primary" | "secondary" | "info" | "success" | "warning" | "error" | "default"> = {
  ip: "info",
  domain: "success",
  hash: "warning",
  email: "secondary",
  bdu: "primary",
  cve: "default",
};

const severityLabels: Record<string, string> = {
  critical: "Критический",
  high: "Высокий",
  medium: "Средний",
  low: "Низкий",
  unknown: "Неизвестно",
};

const threatTypeLabels: Record<string, string> = {
  phishing: "Фишинг",
  malware_attack: "Целевая атака",
  vulnerability: "Уязвимость",
  compromise: "Компрометация",
  clickfix: "ClickFix",
};

const severityColors: Record<string, "error" | "warning" | "info" | "success" | "default"> = {
  critical: "error",
  high: "warning",
  medium: "info",
  low: "success",
  unknown: "default",
};

const sourceLabels: Record<string, string> = {
  nvd: "NVD",
  bdu: "BDU ФСТЭК",
  manual: "Вручную",
};

const letterTypeLabels: Record<string, string> = {
  hacker: "Хакерская группировка",
  compromise: "Компрометация",
  vulnerability: "Уязвимости",
  other: "Прочее",
};

const letterStatusLabels: Record<string, string> = {
  uploaded: "Загружен",
  parsed: "Текст извлечён",
  analyzed: "Проанализирован",
  assessed: "Оценён",
  completed: "Отчёт сформирован",
  failed: "Ошибка обработки",
  deleted: "Удалено",
};

const processingStageLabels: Record<string, string> = {
  uploaded: "Загрузка",
  parsed: "Извлечение текста",
  analyzed: "LLM-анализ",
  assessed: "Проверка уязвимостей",
  done: "Формирование отчёта",
  completed: "Готово",
  failed: "Ошибка",
};

const processingStageProgress: Record<string, number> = {
  uploaded: 10,
  parsed: 35,
  analyzed: 60,
  assessed: 80,
  done: 100,
  completed: 100,
  failed: 100,
};

const entityTypeLabels: Record<string, string> = {
  organization: "Организация",
  deadline: "Срок",
  contact: "Контакт",
};

const applicabilityOptions = [
  { value: "", label: "Не проверено" },
  { value: "true", label: "Используется" },
  { value: "false", label: "Не используется" },
];

const actionTypeOptions = [
  {
    value: "",
    label: "Авто (по умолчанию)",
    desc: "Включить стандартной фразой: обновление ПО либо переход на отечественные ОС (для Windows).",
  },
  {
    value: "update",
    label: "Обновление ПО",
    desc: "Форсировать фразу об обновлении программного обеспечения до неуязвимой версии.",
  },
  {
    value: "compensate",
    label: "Компенсирующие меры",
    desc: "Указать применение компенсирующих мер вместо обновления ПО.",
  },
  {
    value: "skip",
    label: "Не включать",
    desc: "Не вставлять в текст; при совпадении ПО с описанием добавится нота «... не используется».",
  },
  {
    value: "exclude",
    label: "Исключить из ответа",
    desc: "Полностью исключить уязвимость из ответа (BDU не упоминается).",
  },
];

type RiskLevel = "red" | "yellow" | "green" | "gray";

function vulnRiskLevel(v: VulnerabilityResponse): RiskLevel {
  if (v.cmdb_error) return "gray";
  if (v.cmdb_match || v.severity === "critical") return "red";
  if (v.severity === "high" || v.severity === "medium") return "yellow";
  if (v.severity === "unknown" || !v.severity) return "gray";
  return "green";
}

function categorizeRisks(vulns: VulnerabilityResponse[]) {
  let red = 0, yellow = 0, green = 0, gray = 0;
  for (const v of vulns) {
    const lvl = vulnRiskLevel(v);
    if (lvl === "red") red++;
    else if (lvl === "yellow") yellow++;
    else if (lvl === "gray") gray++;
    else green++;
  }
  return { red, yellow, green, gray };
}

const riskStyleMap: Record<RiskLevel, { bg: string; color: string; label: string }> = {
  red: { bg: "#c0392b", color: "#fff", label: "К" },
  yellow: { bg: "#f1c40f", color: "#000", label: "Ж" },
  green: { bg: "#dcfce7", color: "#14532d", label: "З" },
  gray: { bg: "#e5e7eb", color: "#374151", label: "?" },
};

function RiskChip({ level, title }: { level: RiskLevel; title: string }) {
  const s = riskStyleMap[level];
  return (
    <Chip
      size="small"
      label={`${s.label} — ${title}`}
      sx={{ bgcolor: s.bg, color: s.color, fontWeight: "bold", mr: 1 }}
    />
  );
}

function RiskSummary({ summary }: { summary: { red: number; yellow: number; green: number; gray: number } }) {
  return (
    <Paper sx={{ p: 1.5, mb: 2, display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
      <Typography variant="subtitle2" sx={{ mr: 1 }}>Индикаторы уязвимостей:</Typography>
      {summary.red > 0 && <RiskChip level="red" title={`Критические (${summary.red})`} />}
      {summary.yellow > 0 && <RiskChip level="yellow" title={`Средние (${summary.yellow})`} />}
      {summary.green > 0 && <RiskChip level="green" title={`Низкие (${summary.green})`} />}
      {summary.gray > 0 && <RiskChip level="gray" title={`\u041d\u0435 \u043f\u0440\u043e\u0432\u0435\u0440\u0435\u043d\u043e (${summary.gray})`} />}
      {summary.red === 0 && summary.yellow === 0 && summary.green === 0 && summary.gray === 0 && (
        <Typography variant="body2" color="text.secondary">Уязвимости не обнаружены</Typography>
      )}
    </Paper>
  );
}

function TextTab({ letter }: { letter: LetterResponse }) {
  const text = letter.all_text || letter.original_text || "";
  const terms: { value: string; type: string }[] = [];
  const add = (value: string | undefined, type: string) => {
    const v = (value || "").trim();
    if (!v || v.length < 3) return;
    terms.push({ value: v, type });
    if (v.includes(".") && !v.includes(" ")) {
      terms.push({ value: v.replace(/\./g, "[.]"), type });
      terms.push({ value: v.replace(/\./g, "(.)"), type });
    }
  };
  for (const i of letter.iocs) add(i.value, i.ioc_type);
  for (const v of letter.vulnerabilities) {
    add(v.bdu_id, "bdu");
    add(v.cve_id, "cve");
  }
  const unique = Array.from(
    new Map(terms.sort((a, b) => b.value.length - a.value.length).map((t) => [t.value.toLowerCase(), t])).values(),
  );
  const colors: Record<string, string> = {
    ip: "#dbeafe", domain: "#ede9fe", email: "#dcfce7", hash: "#fef3c7",
    cve: "#fee2e2", bdu: "#ffedd5",
  };
  if (!text) {
    return <Alert severity="info">Текст документа отсутствует.</Alert>;
  }
  const pattern = unique.length
    ? new RegExp(`(${unique.map((t) => t.value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})`, "gi")
    : null;
  const parts = pattern ? text.split(pattern) : [text];
  const byValue = new Map(unique.map((t) => [t.value.toLowerCase(), t]));
  return (
    <Paper sx={{ p: 2 }}>
      <Box sx={{ display: "flex", gap: 1, mb: 1, flexWrap: "wrap" }}>
        {["ip", "domain", "email", "hash", "bdu", "cve"].map((t) => (
          <Chip key={t} size="small" label={iocTypeLabels[t] || t.toUpperCase()}
                sx={{ bgcolor: colors[t], fontSize: 11 }} />
        ))}
      </Box>
      <Typography component="pre" sx={{ whiteSpace: "pre-wrap", fontFamily: "monospace", fontSize: 13 }}>
        {parts.map((part, idx) => {
          const hit = byValue.get(part.toLowerCase());
          if (!hit) return <span key={idx}>{part}</span>;
          return (
            <Box component="mark" key={idx}
                 sx={{ bgcolor: colors[hit.type] || "#fef3c7", px: 0.2, borderRadius: 0.4 }}>
              {part}
            </Box>
          );
        })}
      </Typography>
    </Paper>
  );
}

export default function LetterDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [letter, setLetter] = useState<LetterResponse | null>(null);
  const [tab, setTab] = useState(0);
  const [loading, setLoading] = useState(true);
  const [snack, setSnack] = useState("");
  const [loadError, setLoadError] = useState("");
  const [regeneratingReport, setRegeneratingReport] = useState(false);
  const previousStatus = useRef<string | undefined>(undefined);

  const load = async (view = false) => {
    setLoading(true);
    try {
      const { data } = await lettersApi.get(Number(id), view);
      setLetter(data);
      setLoadError("");
    } catch (err: any) {
      setLoadError(err.response?.data?.detail || (err as Error)?.message || "Не удалось загрузить письмо");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(true); }, [id]);

  useEffect(() => {
    if (!letter) return;
    const previous = previousStatus.current;
    if (previous && previous !== letter.status && letter.status === "completed") {
      window.location.reload();
    }
    previousStatus.current = letter.status;
  }, [letter]);

  useEffect(() => {
    if (!letter || ["completed", "failed", "error", "deleted"].includes(letter.status)) return;
    const timer = window.setInterval(async () => {
      try {
        const { data } = await lettersApi.get(Number(id));
        setLetter(data);
      } catch {
        // временная ошибка сети — повторим на следующем тике
      }
    }, 3000);
    return () => window.clearInterval(timer);
  }, [id, letter?.status]);

  const handleGenerate = async () => {
    try {
      await lettersApi.generate(Number(id));
      setSnack("Ответ сгенерирован");
    } catch (err: any) {
      setSnack("Ошибка: " + (err.response?.data?.detail || "неизвестная"));
    }
  };

  const handleExport = async (type: string) => {
    try {
      const { data } = await lettersApi.exportIocs(Number(id), type);
      const url = URL.createObjectURL(data);
      const a = window.document.createElement("a");
      a.href = url;
      const filenames: Record<string, string> = {
        emails: "emails.txt",
        ip_addresses: "ip_addresses.txt",
        domains: "domains.txt",
        ioc_indicators: "ioc_indicators.txt",
      };
      a.download = filenames[type] || `${type}.txt`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setSnack("Ошибка экспорта");
    }
  };

  const handleDownloadReport = async () => {
    try {
      const { data } = await documentsApi.downloadReport(Number(id));
      const url = URL.createObjectURL(data);
      const a = window.document.createElement("a");
      a.href = url;
      a.download = letter?.source_filename
        ? `Report_${letter.source_filename}_${new Date().toISOString().slice(0, 10)}.docx`
        : "report.docx";
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setSnack("Карточка индикаторов ещё не сформирована");
    }
  };

  const handleRegenerateReport = async () => {
    setRegeneratingReport(true);
    try {
      await documentsApi.regenerateReport(Number(id));
      setSnack("Карточка индикаторов перегенерирована");
      await load();
    } catch (err: any) {
      setSnack("Ошибка: " + (err.response?.data?.detail || "не удалось перегенерировать карточку"));
    } finally {
      setRegeneratingReport(false);
    }
  };

  const handleDownloadRaw = async () => {
    try {
      const { data } = await documentsApi.downloadRaw(Number(id));
      const url = URL.createObjectURL(data);
      const a = window.document.createElement("a");
      a.href = url;
      a.download = letter?.source_filename || "source";
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setSnack("Исходный файл не найден");
    }
  };

  const handleExportDocx = async (type: string) => {
    try {
      const { data } = await lettersApi.exportIocsDocx(Number(id), type);
      const url = URL.createObjectURL(data);
      const a = window.document.createElement("a");
      a.href = url;
      const filenames: Record<string, string> = {
        emails: "emails.docx",
        ip_addresses: "ip-адреса на блокировку.docx",
        domains: "Адреса на блокировку.docx",
        ioc_indicators: "ioc_indicators.docx",
      };
      a.download = filenames[type] || `${type}.docx`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setSnack("Ошибка экспорта");
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setSnack("Скопировано");
  };

  if (loading) return <Typography>Загрузка...</Typography>;
  if (!letter) return <Alert severity="error">{loadError || "Письмо не найдено"}</Alert>;

  const riskSummary = categorizeRisks(letter.vulnerabilities);

  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "center", mb: 2, gap: 1 }}>
        <IconButton aria-label="Назад к списку писем" onClick={() => navigate("/letters")}>
          <BackIcon />
        </IconButton>
        <Typography variant="h5" sx={{ flexGrow: 1 }}>
          Письмо № {letter.letter_number || letter.id}
        </Typography>
        <Button
          variant="outlined"
          size="small"
          startIcon={<DownloadIcon />}
          onClick={handleDownloadReport}
          disabled={!letter.processing_stage || letter.processing_stage === "uploaded"}
        >
          Карточка индикаторов
        </Button>
        <Button
          variant="outlined"
          size="small"
          startIcon={<RefreshIcon />}
          onClick={handleRegenerateReport}
          disabled={regeneratingReport || !letter.processing_stage || letter.processing_stage === "uploaded"}
        >
          {regeneratingReport ? "Пересборка..." : "Пересобрать карточку"}
        </Button>
        <Button
          variant="outlined"
          size="small"
          startIcon={<DownloadIcon />}
          onClick={handleDownloadRaw}
        >
          Исходник
        </Button>
      </Box>

      {!["completed", "failed", "error", "deleted"].includes(letter.status) && (
        <Paper sx={{ p: 2, mb: 2, borderRadius: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
            <Typography variant="subtitle2">Обработка письма</Typography>
            <Typography variant="body2" color="text.secondary">
              {Math.max(0, Math.min(100, letter.progress_percent ?? processingStageProgress[letter.processing_stage] ?? 0))}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={Math.max(0, Math.min(100, letter.progress_percent ?? processingStageProgress[letter.processing_stage] ?? 0))}
            sx={{ height: 8, borderRadius: 1 }}
          />
          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
            Этап: {processingStageLabels[letter.processing_stage] || letter.processing_stage || "в очереди"}
            {letter.eta_seconds != null && letter.eta_seconds > 0 ? ` · осталось ~${letter.eta_seconds} с` : ""}
          </Typography>
        </Paper>
      )}

      <RiskSummary summary={riskSummary} />

      {letter.parse_errors && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          Ошибки парсинга: {letter.parse_errors}
        </Alert>
      )}

      <Tabs value={tab} onChange={(_, v) => setTab(v)} variant="scrollable" allowScrollButtonsMobile sx={{ mb: 2 }}>
        <Tab label="Информация" />
        <Tab label={`Угрозы (${letter.threats.length})`} />
        <Tab label={`IOC (${letter.iocs.length})`} />
        <Tab label={`Уязвимости (${letter.vulnerabilities.length})`} />
        <Tab label="Ответ" />
        <Tab label="Экспорт" />
        <Tab label="Текст" />
      </Tabs>

      {tab === 0 && <InfoTab letter={letter} />}
      {tab === 1 && <ThreatsTab letter={letter} onSaved={load} />}
      {tab === 2 && <IocTab iocs={letter.iocs} onCopy={copyToClipboard}
                              letterId={letter.id} onSaved={load} />}
      {tab === 3 && <VulnTab letter={letter} onSaved={load} />}
      {tab === 4 && <ResponseTab letter={letter} onGenerate={handleGenerate} />}
      {tab === 5 && <ExportTab onExport={handleExport} onExportDocx={handleExportDocx} counts={letter.iocs} />}
      {tab === 6 && <TextTab letter={letter} />}

      <Snackbar
        open={!!snack}
        autoHideDuration={3000}
        onClose={() => setSnack("")}
        message={snack}
      />
    </Box>
  );
}

function InfoTab({ letter }: { letter: LetterResponse }) {
  const summary = letter.summaries?.[0];
  const entities = letter.entities || [];
  return (
    <Grid container spacing={2}>
      <Grid size={{ xs: 12, md: 6 }}>
        <Paper sx={{ p: 2 }}>
          <Typography variant="subtitle1" gutterBottom>Основная информация</Typography>
          <Table size="small">
            <TableBody>
              <TableRow><TableCell>Номер</TableCell><TableCell>{letter.letter_number || "—"}</TableCell></TableRow>
              <TableRow><TableCell>Дата</TableCell><TableCell>{letter.letter_date || "—"}</TableCell></TableRow>
              <TableRow>
                <TableCell>Тип</TableCell>
                <TableCell>{letterTypeLabels[letter.letter_type] || letter.letter_type}</TableCell>
              </TableRow>
              <TableRow>
                <TableCell>Статус</TableCell>
                <TableCell>
                  <Chip size="small" variant="outlined"
                        label={letterStatusLabels[letter.status] || letter.status} />
                </TableCell>
              </TableRow>
              <TableRow><TableCell>SLA</TableCell><TableCell>{letter.sla === "critical" ? "Критичный" : "Обычный"}</TableCell></TableRow>
              <TableRow><TableCell>Создано</TableCell><TableCell>{new Date(letter.created_at).toLocaleString("ru-RU")}</TableCell></TableRow>
            </TableBody>
          </Table>
          {summary && (
            <Box sx={{ mt: 2 }}>
              <Typography variant="subtitle2" gutterBottom>Краткое содержание</Typography>
              <Typography variant="body2">{summary.summary}</Typography>
            </Box>
          )}
          {entities.length > 0 && (
            <Box sx={{ mt: 2 }}>
              <Typography variant="subtitle2" gutterBottom>Сущности</Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                {entities.map((e) => (
                  <Chip key={e.id} size="small"
                        label={`${entityTypeLabels[e.entity_type] || e.entity_type}: ${e.value}`} />
                ))}
              </Box>
            </Box>
          )}
        </Paper>
      </Grid>
      <Grid size={{ xs: 12, md: 6 }}>
        <Paper sx={{ p: 2 }}>
          <Typography variant="subtitle1" gutterBottom>Вложения ({letter.attachments.length})</Typography>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Файл</TableCell>
                <TableCell>Тип</TableCell>
                <TableCell>Статус</TableCell>
                <TableCell align="right">Символов</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {letter.attachments.map((a) => (
                <TableRow key={a.id}>
                  <TableCell>{a.filename}</TableCell>
                  <TableCell>{a.file_type}</TableCell>
                  <TableCell>
                    <Chip
        label={["ok", "done"].includes(a.parse_status) ? "OK" : a.parse_status}
        color={["ok", "done"].includes(a.parse_status) ? "success" : "warning"}
                      size="small"
                    />
                  </TableCell>
                  <TableCell align="right">{a.parsed_text.length}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Paper>
      </Grid>
      {letter.parse_errors && (
        <Grid size={{ xs: 12 }}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="subtitle1" color="error" gutterBottom>Ошибки парсинга</Typography>
            <Typography variant="body2" component="pre" sx={{ whiteSpace: "pre-wrap" }}>
              {letter.parse_errors}
            </Typography>
          </Paper>
        </Grid>
      )}
    </Grid>
  );
}

function ThreatsTab({ letter, onSaved }: { letter: LetterResponse; onSaved?: () => void }) {
  const [expanded, setExpanded] = useState<number | null>(null);
  const [editing, setEditing] = useState<ThreatResponse | null>(null);
  const [measuresText, setMeasuresText] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  if (letter.threats.length === 0) {
    return <Alert severity="info">Угрозы не обнаружены</Alert>;
  }

  const openMeasures = (t: ThreatResponse) => {
    setEditing(t);
    setMeasuresText(t.measures || "");
    setError("");
  };

  const saveMeasures = async () => {
    if (!editing) return;
    setSaving(true);
    try {
      const measures = measuresText.split("\n").map((m) => m.trim()).filter(Boolean);
      await lettersApi.updateThreatMeasures(letter.id, editing.id, measures);
      setEditing(null);
      if (onSaved) onSaved();
    } catch (err: any) {
      setError(err.response?.data?.detail || (err as Error)?.message || "Ошибка сохранения");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Box>
      {letter.threats.map((t) => {
        const isExpanded = expanded === t.id;
        const threatText = threatOnlyText(t.description);
        const isLong = threatText.length > 500;
        const measures = (t.measures || "").split("\n").map((m) => m.trim()).filter(Boolean);
        return (
        <Card key={t.id} sx={{ mb: 2 }}>
          <CardContent>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1, flexWrap: "wrap" }}>
              <Chip label={`#${t.number}`} color="primary" size="small" />
              {t.group_name && <Chip label={t.group_name} color="error" size="small" />}
              {t.threat_type && <Chip label={threatTypeLabels[t.threat_type] || t.threat_type} size="small" variant="outlined" />}
              {t.malware_type && <Chip label={t.malware_type} color="warning" size="small" />}
              {t.theme && <Chip label={t.theme} size="small" variant="outlined" />}
            </Box>
            <Typography variant="body2" sx={{ mb: 1, whiteSpace: "pre-wrap" }}>
              {isExpanded ? threatText : threatText.slice(0, 500)}
              {isLong && !isExpanded && "..."}
            </Typography>
            {isLong && (
              <Button size="small" onClick={() => setExpanded(isExpanded ? null : t.id)} sx={{ mb: 1 }}>
                {isExpanded ? "Свернуть" : "Показать полностью"}
              </Button>
            )}
            <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", mb: 1 }}>
              {t.archive_name && (
                <Typography variant="caption" color="text.secondary">
                  Архив: {t.archive_name}
                </Typography>
              )}
              {t.exe_name && (
                <Typography variant="caption" color="text.secondary">
                  Файл: {t.exe_name}
                </Typography>
              )}
            </Box>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
              <Typography variant="subtitle2">Меры защиты ({measures.length})</Typography>
              <Button size="small" onClick={() => openMeasures(t)}>Редактировать</Button>
            </Box>
            {measures.length > 0 ? (
              <Box component="ul" sx={{ m: 0, pl: 3 }}>
                {measures.map((m, i) => (
                  <li key={i}><Typography variant="body2">{m}</Typography></li>
                ))}
              </Box>
            ) : (
              <Typography variant="body2" color="text.secondary">
                Меры не заданы — будут подобраны при генерации ответа
              </Typography>
            )}
          </CardContent>
        </Card>
        );
      })}

      <Dialog open={editing !== null} onClose={() => setEditing(null)} maxWidth="md" fullWidth>
        <DialogTitle>Меры защиты — угроза #{editing?.number}</DialogTitle>
        <DialogContent>
          {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            По одной мере в строке. Пустой список — меры подбираются автоматически.
          </Typography>
          <TextField
            multiline
            minRows={8}
            fullWidth
            value={measuresText}
            onChange={(e) => setMeasuresText(e.target.value)}
            placeholder={"на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам;"}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditing(null)}>Отмена</Button>
          <Button variant="contained" onClick={saveMeasures} disabled={saving}>
            {saving ? "Сохранение..." : "Сохранить"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

function IocTab({ iocs, onCopy, letterId, onSaved }: {
  iocs: IoCResponse[];
  onCopy: (text: string) => void;
  letterId: number;
  onSaved?: (view?: boolean) => void;
}) {
  const types = ["ip", "ip_cidr", "ipv6", "domain", "url", "hash", "email", "bdu", "cve"];
  const reload = () => onSaved?.();
  const editIoc = async (id: number, value: string) => {
    const next = window.prompt("Новое значение IoC", value);
    if (!next || next.trim() === value) return;
    try {
      await lettersApi.updateIoc(letterId, id, { value: next.trim() });
      reload();
    } catch (err: any) {
      window.alert(err.response?.data?.detail || "Не удалось изменить IoC");
    }
  };
  const removeIoc = async (id: number, value: string) => {
    if (!window.confirm(`Удалить IoC ${value}?`)) return;
    try {
      await lettersApi.deleteIoc(letterId, id);
      reload();
    } catch (err: any) {
      window.alert(err.response?.data?.detail || "Не удалось удалить IoC");
    }
  };
  const addIoc = async () => {
    const ioc_type = window.prompt("Тип IoC: ip, ipv6, ip_cidr, domain, email, hash, bdu, cve, url", "ip");
    if (!ioc_type) return;
    const value = window.prompt("Значение IoC");
    if (!value) return;
    try {
      await lettersApi.createIoc(letterId, { value: value.trim(), ioc_type: ioc_type.trim().toLowerCase() });
      reload();
    } catch (err: any) {
      window.alert(err.response?.data?.detail || "Не удалось добавить IoC");
    }
  };
  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "flex-end", mb: 1 }}>
        <Button size="small" variant="outlined" onClick={addIoc}>Добавить IoC</Button>
      </Box>
      {types.map((type) => {
        const filtered = iocs.filter((i) => i.ioc_type === type);
        if (filtered.length === 0) return null;
        return (
          <Paper key={type} sx={{ p: 2, mb: 2 }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
              <Typography variant="subtitle1">
                {iocTypeLabels[type] || type} ({filtered.length})
              </Typography>
              <Button size="small" startIcon={<CopyIcon />}
                onClick={() => onCopy(filtered.map((i) => i.value).join("\n"))}>
                Скопировать
              </Button>
            </Box>
            <TableContainer>
              <Table size="small">
                <TableBody>
                  {filtered.map((ioc) => (
                    <TableRow key={ioc.id} hover>
                      <TableCell sx={{ fontFamily: "monospace" }}>{ioc.value}</TableCell>
                      <TableCell align="right">
                        <IconButton size="small" aria-label={`Скопировать ${ioc.value}`} onClick={() => onCopy(ioc.value)}>
                          <CopyIcon fontSize="small" />
                        </IconButton>
                        <IconButton size="small" aria-label={`Изменить ${ioc.value}`} onClick={() => editIoc(ioc.id, ioc.value)}>
                          <EditIcon fontSize="small" />
                        </IconButton>
                        <IconButton size="small" aria-label={`Удалить ${ioc.value}`} onClick={() => removeIoc(ioc.id, ioc.value)}>
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        );
      })}
      {iocs.length === 0 && <Alert severity="info">IOC не обнаружены</Alert>}
    </Box>
  );
}

function VulnTab({ letter, onSaved }: { letter: LetterResponse; onSaved?: () => void }) {
  const [drafts, setDrafts] = useState<Record<number, {
    action_type: string; software: string;
    applicability: string; applicability_notes: string; action_details: string;
    current_version: string; target_version: string; fixed_version: string;
  }>>({});
  const [savingId, setSavingId] = useState<number | null>(null);
  const [snack, setSnack] = useState("");
  const [editing, setEditing] = useState<Record<number, boolean>>({});
  const [autofilling, setAutofilling] = useState<number | null>(null);

  useEffect(() => {
    setDrafts((prev) => {
      const next = { ...prev };
      for (const v of letter.vulnerabilities) {
        if (!next[v.id]) {
          next[v.id] = {
            action_type: v.action_type,
            software: v.software,
            applicability: v.is_applicable === true ? "true" : v.is_applicable === false ? "false" : "",
            applicability_notes: v.applicability_notes || "",
            action_details: v.action_details || "",
            current_version: v.current_version || "",
            target_version: v.target_version || "",
            fixed_version: v.fixed_version || "",
          };
        }
      }
      return next;
    });
  }, [letter.id, letter.vulnerabilities]);

  if (letter.vulnerabilities.length === 0) {
    return <Alert severity="info">Уязвимости не обнаружены</Alert>;
  }

  const updateDraft = (id: number, patch: Partial<{
    action_type: string; software: string;
    applicability: string; applicability_notes: string; action_details: string;
    current_version: string; target_version: string; fixed_version: string;
  }>) => {
    setDrafts((prev) => ({
      ...prev,
      [id]: { ...(prev[id] || { action_type: "", software: "", applicability: "", applicability_notes: "", action_details: "", current_version: "", target_version: "", fixed_version: "" }), ...patch },
    }));
  };

  const handleSave = async (id: number) => {
    const d = drafts[id];
    if (!d) return;
    setSavingId(id);
    try {
      await lettersApi.updateVulnerability(letter.id, id, {
        action_type: d.action_type,
        software: d.software,
        is_applicable: d.applicability === "" ? null : d.applicability === "true",
        applicability_notes: d.applicability_notes,
        action_details: d.action_details,
        current_version: d.current_version,
        target_version: d.target_version,
        fixed_version: d.fixed_version,
      });
      setSnack("Уязвимость сохранена");
      setEditing((prev) => ({ ...prev, [id]: false }));
      if (onSaved) onSaved();
    } catch (err: any) {
      setSnack("Ошибка: " + (err.response?.data?.detail || "неизвестная"));
    } finally {
      setSavingId(null);
    }
  };

  const handleAutofill = async (id: number) => {
    setAutofilling(id);
    try {
      const { data } = await lettersApi.autofillVulnerability(letter.id, id);
      updateDraft(id, {
        action_type: data.action_type || "",
        applicability: data.applicability === "unknown" ? "" : data.applicability,
        applicability_notes: data.applicability_notes || "",
        action_details: data.action_details || "",
        current_version: data.current_version || drafts[id]?.current_version || "",
      });
      setSnack("Заполнено по CMDB и библиотеке мер. Проверьте перед сохранением.");
    } catch (err: any) {
      setSnack("Ошибка автозаполнения: " + (err.response?.data?.detail || "неизвестная"));
    } finally {
      setAutofilling(null);
    }
  };

  return (
    <Box>
      {letter.vulnerabilities.map((v) => {
        const d = drafts[v.id] || {
          action_type: v.action_type, software: v.software,
          applicability: v.is_applicable === true ? "true" : v.is_applicable === false ? "false" : "",
          applicability_notes: v.applicability_notes || "", action_details: v.action_details || "",
          current_version: v.current_version || "", target_version: v.target_version || "",
          fixed_version: v.fixed_version || "",
        };
        const opt = actionTypeOptions.find((o) => o.value === d.action_type);
        const app = applicabilityOptions.find((o) => o.value === d.applicability);
        return (
          <Card key={v.id} sx={{ mb: 2 }}>
            <CardContent>
              <Box sx={{ display: "flex", gap: 1, mb: 1, flexWrap: "wrap" }}>
                {v.bdu_id && <Chip label={v.bdu_id} size="small" color="info" />}
                {v.cve_id && <Chip label={v.cve_id} size="small" color="info" />}
                <Chip
                  label={severityLabels[v.severity] || v.severity}
                  size="small"
                  color={severityColors[v.severity] || "default"}
                />
                <RiskChip level={vulnRiskLevel(v)} title={vulnRiskLevel(v) === "red" ? "\u0412\u044b\u0441\u043e\u043a\u0438\u0439 \u0440\u0438\u0441\u043a" : vulnRiskLevel(v) === "yellow" ? "\u0421\u0440\u0435\u0434\u043d\u0438\u0439 \u0440\u0438\u0441\u043a" : vulnRiskLevel(v) === "gray" ? "\u041d\u0435 \u043f\u0440\u043e\u0432\u0435\u0440\u0435\u043d\u043e" : "\u041d\u0438\u0437\u043a\u0438\u0439 \u0440\u0438\u0441\u043a"} />
                {v.source && (
                  <Chip
                    label={`Источник: ${sourceLabels[v.source] || v.source}`}
                    size="small"
                    variant="outlined"
                    color={v.source === "manual" ? "default" : "primary"}
                  />
                )}
              </Box>
              {v.description && (
                <Typography variant="body2" sx={{ mb: 2 }}>{v.description.slice(0, 300)}</Typography>
              )}
              {v.cmdb_match && (
                <Alert severity="error" sx={{ mb: 2 }} icon={false}>
                  <Typography variant="body2" sx={{ fontWeight: "bold" }}>
                    Совпадение с инвентаризацией: {v.software && v.current_version
                      ? `${v.software} ${v.current_version}`
                      : (v.software || "Компонент системы")}
                  </Typography>
                  {v.target_version && (
                    <Typography variant="body2">Обновить до версии <b>{v.target_version}</b></Typography>
                  )}
                  {v.recommendation && (
                    <Typography variant="body2" component="div">
                      Рекомендация: {v.recommendation}
                    </Typography>
                  )}
                </Alert>
              )}
              {v.cmdb_error && (
                <Alert severity="warning" sx={{ mb: 1 }}>{`CMDB: ${v.cmdb_error}`}</Alert>
              )}
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mb: 1.5 }}>
                {v.cvss_score != null && <Chip size="small" label={`CVSS ${v.cvss_score}`} color="warning" variant="outlined" />}
                {d.software && <Chip size="small" label={`${d.software}${d.current_version ? ` ${d.current_version}` : ""}`} />}
                {d.target_version && <Chip size="small" color="warning" variant="outlined" label={`\u2192 ${d.target_version}`} />}
                {d.fixed_version && <Chip size="small" color="success" variant="outlined" label={d.fixed_version} />}
                {opt && d.action_type !== "" && <Chip size="small" variant="outlined" label={opt.label} />}
                {app && d.applicability !== "" && <Chip size="small" variant="outlined" color={d.applicability === "true" ? "success" : "default"} label={app.label} />}
              </Box>
              {editing[v.id] ? (
                <>
              <Grid container spacing={2}>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    label="Программное обеспечение"
                    value={d.software}
                    onChange={(e) => updateDraft(v.id, { software: e.target.value })}
                    size="small"
                    fullWidth
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 4 }}>
                  <TextField label="Текущая версия" value={d.current_version}
                    onChange={(e) => updateDraft(v.id, { current_version: e.target.value })}
                    size="small" fullWidth />
                </Grid>
                <Grid size={{ xs: 12, md: 4 }}>
                  <TextField label="Целевая версия" value={d.target_version}
                    onChange={(e) => updateDraft(v.id, { target_version: e.target.value })}
                    size="small" fullWidth />
                </Grid>
                <Grid size={{ xs: 12, md: 4 }}>
                  <TextField label="Исправленная версия" value={d.fixed_version}
                    onChange={(e) => updateDraft(v.id, { fixed_version: e.target.value })}
                    size="small" fullWidth />
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <FormControl fullWidth size="small">
                    <Typography variant="caption" color="text.secondary" sx={{ mb: 0.5 }}>
                      ПО используется
                    </Typography>
                    <Select
                      value={d.applicability}
                      onChange={(e) => updateDraft(v.id, { applicability: e.target.value })}
                      displayEmpty
                    >
                      {applicabilityOptions.map((o) => (
                        <MenuItem key={o.value} value={o.value}>{o.label}</MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <FormControl fullWidth size="small">
                    <Typography variant="caption" color="text.secondary" sx={{ mb: 0.5 }}>
                      Действие по уязвимости
                    </Typography>
                    <Select
                      value={d.action_type}
                      onChange={(e) => updateDraft(v.id, { action_type: e.target.value })}
                    >
                      {actionTypeOptions.map((o) => (
                        <MenuItem key={o.value} value={o.value}>
                          {o.label}
                        </MenuItem>
                      ))}
                    </Select>
                    {opt && (
                      <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: "block" }}>
                        {opt.desc}
                      </Typography>
                    )}
                  </FormControl>
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    label="Детали действия"
                    value={d.action_details}
                    onChange={(e) => updateDraft(v.id, { action_details: e.target.value })}
                    size="small"
                    fullWidth
                    placeholder="Например: обновить до версии 2.17.0 до 01.06.2026"
                  />
                </Grid>
                <Grid size={{ xs: 12 }}>
                  <TextField
                    label="Обоснование использования ПО"
                    value={d.applicability_notes}
                    onChange={(e) => updateDraft(v.id, { applicability_notes: e.target.value })}
                    size="small"
                    fullWidth
                    multiline
                    minRows={1}
                    placeholder="Почему ПО используется или не используется (CMDB, версия, конфигурация)"
                  />
                </Grid>
              </Grid>
                  <Box sx={{ display: "flex", justifyContent: "flex-end", mt: 2, gap: 1 }}>
                    <Button
                      variant="outlined"
                      size="small"
                      startIcon={<AutoFixHighIcon />}
                      onClick={() => handleAutofill(v.id)}
                      disabled={autofilling === v.id || savingId === v.id}
                    >{autofilling === v.id ? "Заполнение..." : "Заполнить"}</Button>
                    <Button
                      variant="text"
                      size="small"
                      onClick={() => {
                        setDrafts((prev) => ({
                          ...prev,
                          [v.id]: {
                            action_type: v.action_type,
                            software: v.software,
                            applicability: v.is_applicable === true ? "true" : v.is_applicable === false ? "false" : "",
                            applicability_notes: v.applicability_notes || "",
                            action_details: v.action_details || "",
                            current_version: v.current_version || "",
                            target_version: v.target_version || "",
                            fixed_version: v.fixed_version || "",
                          },
                        }));
                        setEditing((prev) => ({ ...prev, [v.id]: false }));
                      }}
                    >{"\u041e\u0442\u043c\u0435\u043d\u0430"}</Button>
                    <Button
                      variant="contained"
                      size="small"
                      onClick={() => handleSave(v.id)}
                      disabled={savingId === v.id}
                    >{savingId === v.id ? "\u0421\u043e\u0445\u0440\u0430\u043d\u0435\u043d\u0438\u0435..." : "\u0421\u043e\u0445\u0440\u0430\u043d\u0438\u0442\u044c"}</Button>
                  </Box>
                </>
              ) : (
                <Box sx={{ display: "flex", justifyContent: "flex-end" }}>
                  <Button
                    variant="outlined"
                    size="small"
                    startIcon={<EditIcon />}
                    onClick={() => setEditing((prev) => ({ ...prev, [v.id]: true }))}
                  >{"\u0418\u0437\u043c\u0435\u043d\u0438\u0442\u044c"}</Button>
                </Box>
              )}
            </CardContent>
          </Card>
        );
      })}
      <Snackbar
        open={!!snack}
        autoHideDuration={3000}
        onClose={() => setSnack("")}
        message={snack}
      />
    </Box>
  );
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

const threatCutMarkers = [
  "Для предотвращения реализации угроз безопасности информации",
  "В целях предотвращения возможности эксплуатации указанной уязвимости",
  "В целях предотвращения возможности эксплуатации указанных уязвимостей",
  "В целях предотвращения реализации угроз безопасности информации",
];

function threatOnlyText(text: string): string {
  let cut = text.length;
  for (const m of threatCutMarkers) {
    const idx = text.indexOf(m);
    if (idx !== -1 && idx < cut) cut = idx;
  }
  const attachment = text.search(/[Вв]о\s+вложени/);
  if (attachment !== -1 && attachment < cut) cut = attachment;
  return text.slice(0, cut).replace(/\s+$/g, "");
}

function normMeasure(s: string): string {
  return s.toLowerCase().replace(/\s+/g, " ").replace(/[;.\s]+$/g, "").trim();
}

function buildHighlightedHtml(text: string, iocs: IoCResponse[], measureOptions: string[],
                              baseMeasures: string[], aiMeasures: string[] = []): string {
  const escaped = escapeHtml(text);
  const patterns: { re: RegExp; cls: string }[] = [];

  const hashIocs = iocs.filter((i) => i.ioc_type === "hash").map((i) => i.value);
  const ipIocs = iocs.filter((i) => ["ip", "ip_cidr", "ipv6"].includes(i.ioc_type)).map((i) => i.value);
  const domainIocs = iocs.filter((i) => i.ioc_type === "domain").map((i) => i.value);
  const emailIocs = iocs.filter((i) => i.ioc_type === "email").map((i) => i.value);

  for (const h of hashIocs) patterns.push({ re: new RegExp(h.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g"), cls: "hl-hash" });
  for (const ip of ipIocs) patterns.push({ re: new RegExp(ip.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g"), cls: "hl-ip" });
  for (const d of domainIocs) patterns.push({ re: new RegExp(d.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g"), cls: "hl-domain" });
  for (const e of emailIocs) patterns.push({ re: new RegExp(e.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g"), cls: "hl-email" });

  // базовые меры (из default-шаблона типа угрозы) — синяя подсветка;
  // компенсирующие/нетипичные меры, не входящие в базовый набор, — оранжевая
  const baseSet = new Set((baseMeasures || []).map(normMeasure));
  const aiSet = new Set((aiMeasures || []).map(normMeasure));
  for (const measure of measureOptions) {
    if (measure && measure.length > 15) {
      const key = normMeasure(measure);
      const cls = aiSet.has(key) ? "hl-measure-ai"
        : baseSet.has(key) ? "hl-measure" : "hl-measure-unknown";
      patterns.push({ re: new RegExp(measure.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g"), cls });
    }
  }

  const marks: { start: number; end: number; cls: string; rank: number }[] = [];
  const rank = (cls: string) =>
    cls === "hl-measure-ai" ? 2 : cls === "hl-measure" ? 1 : 0;
  for (const { re, cls } of patterns) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(escaped)) !== null) {
      if (m[0].length === 0) { re.lastIndex++; continue; }
      marks.push({ start: m.index, end: m.index + m[0].length, cls, rank: rank(cls) });
    }
  }
  marks.sort((a, b) => a.start - b.start || b.end - a.end || b.rank - a.rank);
  const filtered: typeof marks = [];
  let lastEnd = -1;
  for (const mk of marks) {
    if (mk.start >= lastEnd) {
      filtered.push(mk);
      lastEnd = mk.end;
    }
  }

  let result = "";
  let pos = 0;
  for (const mk of filtered) {
    result += escaped.slice(pos, mk.start);
    result += `<mark class="${mk.cls}">${escaped.slice(mk.start, mk.end)}</mark>`;
    pos = mk.end;
  }
  result += escaped.slice(pos);
  return result;
}

function ResponseTab({ letter, onGenerate }: { letter: LetterResponse; onGenerate: () => Promise<void> }) {
  const [preview, setPreview] = useState<{
    title: string;
    intro: string;
    sections: Array<{
      threat_id: number;
      number: number;
      prefix: string;
      description: string;
      measures: string[];
      measures_preview: string[];
      measure_annotations?: Array<{
        text: string;
        source: string;
        candidate_id?: number | null;
      }>;
      threat_type: string;
      measure_options: string[];
      base_measures: string[];
      intro_text: string;
      section_text: string;
    }>;
  } | null>(null);
  const [editText, setEditText] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [snack, setSnack] = useState("");
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const buildText = (data: typeof preview) => {
    if (!data) return "";
    const sections = data.sections.map((s) => {
      const intro = `${s.prefix}В целях предотвращения возможности реализации угроз безопасности информации, связанных с ${s.description}, приняты следующие меры защиты:`;
      const measures = (s.measures_preview ?? s.measures).map((m) => `\n  ${m}`).join("");
      return intro + measures;
    });
    return `${data.title}\n\n${data.intro}\n\n${sections.join("\n\n")}`;
  };

  const loadPreview = async () => {
    try {
      const { data } = await lettersApi.getResponsePreview(letter.id);
      setPreview(data);
      let savedText = "";
      try {
        const saved = await lettersApi.getResponseText(letter.id);
        if (saved.data?.exists && saved.data.text) {
          savedText = saved.data.text;
        }
      } catch {
        savedText = "";
      }
      setEditText(savedText || data.text || buildText(data));
      if (savedText) {
        setSnack("Загружена сохранённая версия ответа");
      }
    } catch (err: any) {
      setSnack("Ошибка: " + (err.response?.data?.detail || "не удалось загрузить ответ"));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadPreview(); }, [letter.id]);

  const handleGenerate = async () => {
    setLoading(true);
    await onGenerate();
    await loadPreview();
  };

  const handleDownloadDocx = async () => {
    try {
      const { data } = await lettersApi.download(letter.id);
      const url = URL.createObjectURL(data);
      const a = window.document.createElement("a");
      a.href = url;
      a.download = `Ответ на письмо ${letter.letter_number || letter.id}.docx`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error((err as Error)?.message || "Error");
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await lettersApi.updateResponse(letter.id, editText);
      setSnack("Сохранено");
    } catch (err) {
      setSnack("Ошибка сохранения");
    } finally {
      setSaving(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setSnack("Скопировано");
  };

  const allMeasureOptions = preview
    ? preview.sections.flatMap((s) => s.measure_options || []).filter(Boolean)
    : [];

  const aiMeasures = preview
    ? Array.from(
        new Map(
          preview.sections
            .flatMap((s) => s.measure_annotations || [])
            .filter((a) => a.source === "new" && a.text)
            .map((a) => [normMeasure(a.text), a] as const)
        ).values()
      )
    : [];
  const aiKeys = new Set(aiMeasures.map((a) => normMeasure(a.text)));

  const unknownMeasures = preview
    ? Array.from(
        new Set(
          preview.sections
            .flatMap((s) => s.measure_options || [])
            .filter(Boolean)
            .filter((opt) => opt.length > 15)
            .filter((opt) => !aiKeys.has(normMeasure(opt)))
            .filter((opt) => {
              const base = new Set(preview!.sections.flatMap((sec) => (sec.base_measures || []).map(normMeasure)).filter(Boolean));
              return !base.has(normMeasure(opt));
            })
        )
      )
    : [];

  const groupedTemplates = preview
    ? preview.sections.reduce(
        (acc, s) => {
          if (!acc[s.threat_type]) {
            acc[s.threat_type] = { type: s.threat_type, options: [] };
          }
          for (const opt of s.measure_options) {
            if (opt && !acc[s.threat_type].options.includes(opt)) {
              acc[s.threat_type].options.push(opt);
            }
          }
          return acc;
        },
        {} as Record<string, { type: string; options: string[] }>
      )
    : {};

  const renderIocGroup = (label: string, types: string[]) => {
    const items = letter.iocs.filter((i) => types.includes(i.ioc_type));
    if (items.length === 0) return null;
    return (
      <Box sx={{ mb: 1.5 }}>
        <Typography variant="caption" sx={{ fontWeight: "bold", display: "block", mb: 0.5, textTransform: "uppercase", color: "text.secondary" }}>
          {label} ({items.length})
        </Typography>
        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
          {items.map((ioc) => (
            <Chip
              key={ioc.id}
              label={ioc.value.length > 30 ? ioc.value.slice(0, 30) + "..." : ioc.value}
              size="small"
              color={iocChipColors[ioc.ioc_type] || "default"}
              onClick={() => copyToClipboard(ioc.value)}
              title={`Кликнуть чтобы скопировать: ${ioc.value}`}
              sx={{ cursor: "pointer", fontFamily: "monospace", fontSize: "0.7rem" }}
            />
          ))}
        </Box>
      </Box>
    );
  };

  if (loading) return <Typography>Загрузка...</Typography>;

  return (
    <Box>
      <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap" }}>
        <Button variant="outlined" startIcon={<RefreshIcon />} onClick={handleGenerate}>
          Сгенерировать заново
        </Button>
        <Button variant="contained" startIcon={<DownloadIcon />} onClick={handleDownloadDocx} disabled={!preview}>
          Скачать DOCX
        </Button>
        <Button variant="outlined" onClick={handleSave} disabled={!preview}>
          {saving ? "Сохранение..." : "Сохранить"}
        </Button>
      </Box>

      {aiMeasures.length > 0 && (
        <Alert severity="warning" icon={<AutoFixHighIcon />} sx={{ mb: 2 }}>
          <Typography variant="body2" sx={{ fontWeight: "bold", mb: 0.5 }}>
            В ответе есть меры, сгенерированные ИИ ({aiMeasures.length})
          </Typography>
          <Typography variant="body2" sx={{ mb: 1 }}>
            Они выделены фиолетовым и не входят в базовую библиотеку. Проверьте их перед сохранением
            и отправкой ответа.
          </Typography>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
            {aiMeasures.map((a) => (
              <Box key={normMeasure(a.text)} sx={{ display: "flex", gap: 1, alignItems: "flex-start" }}>
                <Chip label="ИИ" size="small" color="secondary" sx={{ mt: 0.2 }} />
                <Typography variant="caption" sx={{ whiteSpace: "normal", wordBreak: "break-word" }}>
                  {a.text}
                </Typography>
              </Box>
            ))}
          </Box>
        </Alert>
      )}

      {!preview ? (
        <Alert severity="info">Нажмите «Сгенерировать заново» для создания ответа</Alert>
      ) : (
        <Grid container spacing={2}>
          <Grid size={{ xs: 12, md: 8 }}>
            <Paper
              variant="outlined"
              sx={{
                position: "relative",
                fontFamily: "Times New Roman, serif",
                fontSize: "0.9rem",
                lineHeight: 1.5,
                "& mark": { borderRadius: "2px", padding: "0 1px" },
                "& .hl-hash": { backgroundColor: "#fff3bf" },
                "& .hl-ip": { backgroundColor: "#d0ebff" },
                "& .hl-domain": { backgroundColor: "#d3f9d8" },
                "& .hl-email": { backgroundColor: "#ffec99" },
                "& .hl-measure": { backgroundColor: "#e7f5ff", borderBottom: "1px dashed #1976d2" },
                "& .hl-measure-ai": { backgroundColor: "#f3e8ff", borderBottom: "2px solid #7b1fa2" },
                "& .hl-measure-unknown": { backgroundColor: "#ffe8cc", borderBottom: "1px dashed #f76707" },
                "& textarea::selection": { backgroundColor: "rgba(25, 118, 210, 0.3)" },
              }}
            >
              <Box
                aria-hidden
                component="pre"
                sx={{
                  position: "absolute",
                  top: 0, left: 0, right: 0, bottom: 0,
                  margin: 0, padding: "16px",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                  pointerEvents: "none",
                  overflow: "auto",
                  fontFamily: "inherit",
                  fontSize: "inherit",
                  lineHeight: "inherit",
                  color: "#000",
                }}
                dangerouslySetInnerHTML={{ __html: buildHighlightedHtml(editText, letter.iocs, allMeasureOptions, preview ? preview.sections.flatMap((s) => s.base_measures || []).filter(Boolean) : [], aiMeasures.map((a) => a.text)) + "\n" }}
              />
              <textarea
                ref={textareaRef}
                value={editText}
                onChange={(e) => setEditText(e.target.value)}
                onScroll={(e) => {
                  const ta = e.currentTarget;
                  const pre = ta.previousElementSibling;
                  if (pre) {
                    pre.scrollTop = ta.scrollTop;
                    pre.scrollLeft = ta.scrollLeft;
                  }
                }}
                spellCheck={false}
                aria-label="Текст ответа на письмо"
                style={{
                  position: "relative",
                  display: "block",
                  width: "100%",
                  minHeight: "60vh",
                  padding: "16px",
                  margin: 0,
                  border: "none",
                  outline: "none",
                  resize: "vertical",
                  background: "transparent",
                  color: "transparent",
                  caretColor: "#000",
                  fontFamily: "inherit",
                  fontSize: "inherit",
                  lineHeight: "inherit",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                  overflow: "auto",
                  WebkitTextFillColor: "transparent",
                }}
              />
            </Paper>
          </Grid>

          <Grid size={{ xs: 12, md: 4 }}>
            <Box sx={{ position: "sticky", top: 16, maxHeight: "calc(100vh - 100px)", overflowY: "auto" }}>
              <Typography variant="subtitle2" sx={{ mb: 1 }}>
                Шаблоны мер (клик — копировать)
              </Typography>
              {Object.entries(groupedTemplates).map(([type, group]) => (
                <Accordion key={type} defaultExpanded={Object.keys(groupedTemplates).length === 1} disableGutters sx={{ mb: 0.5, "&:before": { display: "none" } }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ minHeight: 36, "& .MuiAccordionSummary-content": { m: 0 } }}>
                    <Typography variant="body2" sx={{ fontWeight: "medium" }}>
                      {threatTypeLabels[type] || type} ({group.options.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails sx={{ p: 1, pt: 0.5 }}>
                    <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
                      {group.options.map((opt) => (
                        <Button
                          key={opt}
                          size="small"
                          variant="text"
                          sx={{
                            textAlign: "left",
                            justifyContent: "flex-start",
                            fontSize: "0.72rem",
                            textTransform: "none",
                            whiteSpace: "normal",
                            wordBreak: "break-word",
                            p: 0.5,
                            lineHeight: 1.3,
                            color: "text.primary",
                          }}
                          onClick={() => copyToClipboard(opt)}
                          title={opt}
                        >
                          {opt}
                        </Button>
                      ))}
                    </Box>
                  </AccordionDetails>
                </Accordion>
              ))}

              <Divider sx={{ my: 2 }} />

              <Typography variant="subtitle2" sx={{ mb: 1, color: "secondary.main" }}>
                Меры, сгенерированные ИИ ({aiMeasures.length}) — требуют проверки
              </Typography>
              {aiMeasures.length > 0 ? (
                <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5, mb: 2 }}>
                  {aiMeasures.map((a) => (
                    <Button
                      key={normMeasure(a.text)}
                      size="small"
                      variant="outlined"
                      color="secondary"
                      sx={{
                        textAlign: "left",
                        justifyContent: "flex-start",
                        fontSize: "0.72rem",
                        textTransform: "none",
                        whiteSpace: "normal",
                        wordBreak: "break-word",
                        p: 0.5,
                        lineHeight: 1.3,
                      }}
                      onClick={() => copyToClipboard(a.text)}
                      title={`Сгенерировано LLM. Клик — копировать.\n${a.text}`}
                    >
                      <Chip label="ИИ" size="small" color="secondary" sx={{ mr: 1 }} />
                      {a.text}
                    </Button>
                  ))}
                </Box>
              ) : (
                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 2 }}>
                  Нет мер, сгенерированных ИИ
                </Typography>
              )}

              <Divider sx={{ my: 2 }} />

              <Typography variant="subtitle2" sx={{ mb: 1, color: "warning.main" }}>
                Компенсирующие / нетипичные меры ({unknownMeasures.length}) — требуют проверки
              </Typography>
              {unknownMeasures.length > 0 ? (
                <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5, mb: 2 }}>
                  {unknownMeasures.map((opt) => (
                    <Button
                      key={opt}
                      size="small"
                      variant="outlined"
                      color="warning"
                      sx={{
                        textAlign: "left",
                        justifyContent: "flex-start",
                        fontSize: "0.72rem",
                        textTransform: "none",
                        whiteSpace: "normal",
                        wordBreak: "break-word",
                        p: 0.5,
                        lineHeight: 1.3,
                      }}
                      onClick={() => copyToClipboard(opt)}
                      title={`Не входит в базовый набор мер. Клик — копировать.\n${opt}`}
                    >
                      {opt}
                    </Button>
                  ))}
                </Box>
              ) : (
                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 2 }}>
                  Нет нетипичных мер
                </Typography>
              )}

              <Divider sx={{ my: 2 }} />

              <Typography variant="subtitle2" sx={{ mb: 1 }}>
                IoC ({letter.iocs.length}) — клик копирует
              </Typography>
              {renderIocGroup(iocTypeLabels.ip, ["ip", "ip_cidr", "ipv6"])}
              {renderIocGroup(iocTypeLabels.domain, ["domain"])}
              {renderIocGroup(iocTypeLabels.url, ["url"])}
              {renderIocGroup(iocTypeLabels.hash, ["hash"])}
              {renderIocGroup(iocTypeLabels.email, ["email"])}
              {renderIocGroup(iocTypeLabels.bdu, ["bdu"])}
              {renderIocGroup(iocTypeLabels.cve, ["cve"])}
              {letter.iocs.length === 0 && (
                <Typography variant="caption" color="text.secondary">Нет IoC</Typography>
              )}
            </Box>
          </Grid>
        </Grid>
      )}

      <Snackbar
        open={!!snack}
        autoHideDuration={2000}
        onClose={() => setSnack("")}
        message={snack}
      />
    </Box>
  );
}

function ExportTab({ onExport, onExportDocx, counts }: { onExport: (type: string) => void; onExportDocx: (type: string) => void; counts: IoCResponse[] }) {
  const exportTypes = [
    { type: "emails", label: "Email-адреса", count: counts.filter((i) => i.ioc_type === "email").length },
    { type: "ip_addresses", label: "IP-адреса (на блокировку)", count: counts.filter((i) => ["ip", "ip_cidr", "ipv6"].includes(i.ioc_type)).length },
    { type: "domains", label: "Домены (на блокировку)", count: counts.filter((i) => i.ioc_type === "domain").length },
    { type: "ioc_indicators", label: "Все IOC (IP + домены + хэши + email + BDU + CVE)", count: counts.length },
  ];

  return (
    <Box>
      <Typography variant="subtitle1" gutterBottom>Экспорт IOC-файлов</Typography>
      <Grid container spacing={2}>
        {exportTypes.map((et) => (
          <Grid size={{ xs: 12, md: 6 }} key={et.type}>
            <Card>
              <CardContent>
                <Typography variant="subtitle2">{et.label}</Typography>
                <Typography variant="h6" color="primary">{et.count} записей</Typography>
                <Box sx={{ display: "flex", gap: 1, mt: 1 }}>
                  <Button
                    variant="contained"
                    size="small"
                    startIcon={<DownloadIcon />}
                    onClick={() => onExportDocx(et.type)}
                    disabled={et.count === 0}
                  >
                    DOCX
                  </Button>
                  <Button
                    variant="outlined"
                    size="small"
                    startIcon={<DownloadIcon />}
                    onClick={() => onExport(et.type)}
                    disabled={et.count === 0}
                  >
                    TXT
                  </Button>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>
    </Box>
  );
}
