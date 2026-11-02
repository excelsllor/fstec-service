import { useCallback, useRef, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Chip,
  Divider,
  Grid,
  IconButton,
  LinearProgress,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Paper,
  Typography,
} from "@mui/material";
import {
  CheckCircleOutlined,
  CloudUpload as UploadIcon,
  DeleteOutlined,
  Description as FileIcon,
  FolderOpen,
  InsertDriveFile,
} from "@mui/icons-material";
import { useNavigate } from "react-router-dom";
import { lettersApi } from "../api/client";

const MAX_FILES = 10;
const MAX_FILE_MB = 20;
const ALLOWED_EXT = [".pdf", ".doc", ".docx", ".odt", ".xlsx", ".rtf", ".txt"];

function extOf(name: string) {
  const i = name.lastIndexOf(".");
  return i >= 0 ? name.slice(i).toLowerCase() : "";
}

function sizeText(bytes: number) {
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} МБ`;
  return `${Math.max(1, Math.round(bytes / 1024))} КБ`;
}

export default function Upload() {
  const navigate = useNavigate();
  const [files, setFiles] = useState<File[]>([]);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const addFiles = useCallback((incoming: FileList | File[] | null) => {
    if (!incoming || incoming.length === 0) return;
    setError("");
    setNotice("");
    const arr = Array.from(incoming);
    const badExt = arr.filter((f) => !ALLOWED_EXT.includes(extOf(f.name)));
    const tooBig = arr.filter((f) => f.size > MAX_FILE_MB * 1024 * 1024);
    if (badExt.length) {
      setError(`Неподдерживаемые файлы: ${badExt.map((f) => f.name).join(", ")}. Допустимо: ${ALLOWED_EXT.join(", ")}`);
      return;
    }
    if (tooBig.length) {
      setError(`Файлы больше ${MAX_FILE_MB} МБ: ${tooBig.map((f) => f.name).join(", ")}`);
      return;
    }
    setFiles((prev) => {
      const next = [...prev, ...arr];
      if (next.length > MAX_FILES) {
        setError(`Максимум ${MAX_FILES} файлов за один пакет`);
      }
      return next.slice(0, MAX_FILES);
    });
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (!uploading) addFiles(e.dataTransfer.files);
  }, [addFiles, uploading]);

  const removeFile = (index: number) => {
    setFiles((prev) => prev.filter((_, i) => i !== index));
    setError("");
  };

  const handleUpload = async () => {
    if (files.length === 0 || uploading) return;
    setUploading(true);
    setError("");
    setNotice("");
    try {
      const { data } = await lettersApi.upload(files);
      setNotice(data.duplicate ? "Этот документ уже был загружен — открываю существующую карточку." : "Пакет принят в обработку.");
      navigate(`/letters/${data.id}`);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Не удалось загрузить пакет. Проверьте соединение и формат файлов.");
    } finally {
      setUploading(false);
    }
  };

  const totalBytes = files.reduce((sum, f) => sum + f.size, 0);
  const canUpload = files.length > 0 && !uploading;

  return (
    <Box sx={{ maxWidth: 1180, mx: "auto" }}>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700 }}>Загрузка писем</Typography>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError("")}>{error}</Alert>}
      {notice && <Alert severity="success" sx={{ mb: 2 }}>{notice}</Alert>}
      {uploading && (
        <Paper sx={{ p: 2, mb: 2 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
            <CheckCircleOutlined color="primary" fontSize="small" />
            <Typography variant="body2">Отправляем пакет и запускаем обработку…</Typography>
          </Box>
          <LinearProgress />
        </Paper>
      )}

      <Grid container spacing={3}>
        <Grid size={{ xs: 12 }}>
          <Paper
            role="button"
            tabIndex={0}
            aria-label="Загрузить документы: drag-and-drop или выбор файлов"
            onClick={() => !uploading && inputRef.current?.click()}
            onKeyDown={(e) => {
              if ((e.key === "Enter" || e.key === " ") && !uploading) {
                e.preventDefault();
                inputRef.current?.click();
              }
            }}
            onDragOver={(e) => { e.preventDefault(); if (!uploading) setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            sx={{
              p: { xs: 3, md: 5 },
              textAlign: "center",
              border: "2px dashed",
              borderColor: dragOver ? "primary.main" : files.length ? "success.main" : "divider",
              bgcolor: dragOver ? "primary.50" : "background.paper",
              cursor: uploading ? "default" : "pointer",
              transition: "border-color .2s, background-color .2s, transform .2s",
              transform: dragOver ? "scale(1.005)" : "none",
              borderRadius: 3,
              mb: 2,
            }}
          >
            <input
              ref={inputRef}
              type="file"
              multiple
              hidden
              accept={ALLOWED_EXT.join(",")}
              onChange={(e) => { addFiles(e.target.files); e.target.value = ""; }}
            />
            <Box sx={{
              width: 72, height: 72, borderRadius: "50%", mx: "auto", mb: 2,
              display: "flex", alignItems: "center", justifyContent: "center",
              bgcolor: "primary.50", color: "primary.main",
            }}>
              <UploadIcon sx={{ fontSize: 40 }} />
            </Box>
            <Typography variant="h6" sx={{ fontWeight: 600 }}>
              Перетащите файлы сюда
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
              или <Box component="span" sx={{ color: "primary.main", fontWeight: 600 }}>нажмите для выбора</Box>
            </Typography>
            <Box sx={{ display: "flex", justifyContent: "center", gap: 0.7, flexWrap: "wrap", mt: 2 }}>
              {ALLOWED_EXT.map((ext) => (
                <Chip key={ext} label={ext.toUpperCase()} size="small" variant="outlined" />
              ))}
            </Box>
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1.5 }}>
              До {MAX_FILES} файлов · до {MAX_FILE_MB} МБ каждый · PDF, DOC/DOCX, RTF, ODT, XLSX, TXT
            </Typography>
          </Paper>

          <Paper sx={{ p: 2.5, mb: 2, borderRadius: 3 }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <FolderOpen color="action" />
                <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Файлы пакета</Typography>
                <Chip size="small" label={`${files.length} / ${MAX_FILES}`} />
              </Box>
              <Typography variant="caption" color="text.secondary">
                {files.length ? `Всего: ${sizeText(totalBytes)}` : "Пакет пуст"}
              </Typography>
            </Box>
            <Divider />
            {files.length === 0 ? (
              <Box sx={{ py: 4, textAlign: "center", color: "text.secondary" }}>
                <InsertDriveFile sx={{ fontSize: 38, mb: 1, opacity: 0.5 }} />
                <Typography variant="body2">Файлы ещё не выбраны</Typography>
              </Box>
            ) : (
              <List dense disablePadding>
                {files.map((f, i) => (
                  <ListItem
                    key={`${f.name}-${i}`}
                    divider={i < files.length - 1}
                    secondaryAction={
                      <IconButton edge="end" aria-label="Удалить файл" disabled={uploading} onClick={() => removeFile(i)}>
                        <DeleteOutlined />
                      </IconButton>
                    }
                  >
                    <ListItemIcon sx={{ minWidth: 40 }}>
                      <FileIcon color={extOf(f.name) === ".pdf" ? "error" : "primary"} />
                    </ListItemIcon>
                    <ListItemText
                      primary={f.name}
                      secondary={`${extOf(f.name).replace(".", "").toUpperCase() || "FILE"} · ${sizeText(f.size)}`}
                      slotProps={{ primary: { noWrap: true }, secondary: { noWrap: true } }}
                    />
                  </ListItem>
                ))}
              </List>
            )}
          </Paper>

          <Button
            variant="contained"
            size="large"
            fullWidth
            disabled={!canUpload}
            onClick={handleUpload}
            startIcon={<UploadIcon />}
            sx={{ py: 1.4, borderRadius: 2, fontWeight: 600 }}
          >
            {uploading ? "Загрузка и обработка…" : `Загрузить и обработать${files.length ? ` (${files.length})` : ""}`}
          </Button>
        </Grid>

      </Grid>
    </Box>
  );
}
