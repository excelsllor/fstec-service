import { useEffect, useMemo, useState } from "react";
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
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  IconButton,
  Alert,
  Tabs,
  Tab,
  Switch,
} from "@mui/material";
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  ArrowUpward as ArrowUpwardIcon,
  ArrowDownward as ArrowDownwardIcon,
  RemoveCircleOutlined as RemoveCircleOutlineIcon,
} from "@mui/icons-material";
import {
  templatesApi,
  type ThreatTypeResponse,
  type MeasureTemplateResponse,
  type VulnMeasureTemplateResponse,
} from "../../api/client";

export default function Templates() {
  const [tab, setTab] = useState(0);
  const [threatTypes, setThreatTypes] = useState<ThreatTypeResponse[]>([]);
  const [measureTemplates, setMeasureTemplates] = useState<MeasureTemplateResponse[]>([]);
  const [vulnTemplates, setVulnTemplates] = useState<VulnMeasureTemplateResponse[]>([]);
  const [, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const [tt, mt, vt] = await Promise.all([
        templatesApi.listThreatTypes(),
        templatesApi.listMeasureTemplates(),
        templatesApi.listVulnTemplates(),
      ]);
      setThreatTypes(tt.data);
      setMeasureTemplates(mt.data);
      setVulnTemplates(vt.data);
    } catch (err) {
      console.error((err as Error)?.message || "Error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  return (
    <Box>
      <Typography variant="h5" gutterBottom>Шаблоны</Typography>
      <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2 }}>
        <Tab label="Типы угроз" />
        <Tab label="Блоки мер" />
        <Tab label="Шаблоны уязвимостей" />
      </Tabs>

      {tab === 0 && <ThreatTypesTab items={threatTypes} onChanged={load} />}
      {tab === 1 && <MeasureTemplatesTab items={measureTemplates} threatTypes={threatTypes} onChanged={load} />}
      {tab === 2 && <VulnTemplatesTab items={vulnTemplates} onChanged={load} />}
    </Box>
  );
}

function ThreatTypesTab({ items, onChanged }: { items: ThreatTypeResponse[]; onChanged: () => void }) {
  const [dialog, setDialog] = useState<"create" | "edit" | "delete" | null>(null);
  const [editing, setEditing] = useState<ThreatTypeResponse | null>(null);
  const [form, setForm] = useState({ name: "", key: "", description: "" });
  const [error, setError] = useState("");

  const handleCreate = async () => {
    setError("");
    try {
      await templatesApi.createThreatType(form);
      setDialog(null);
      setForm({ name: "", key: "", description: "" });
      onChanged();
    } catch (err: any) {
      setError(err.response?.data?.detail || "Ошибка");
    }
  };

  const handleEdit = async () => {
    if (!editing) return;
    try {
      await templatesApi.updateThreatType(editing.id, { name: form.name, description: form.description });
      setDialog(null);
      onChanged();
    } catch (err: any) {
      setError(err.response?.data?.detail || "Ошибка");
    }
  };

  const handleDelete = async () => {
    if (!editing) return;
    try {
      await templatesApi.deleteThreatType(editing.id);
      setDialog(null);
      setEditing(null);
      onChanged();
    } catch (err: any) {
      setError(err.response?.data?.detail || "Ошибка");
    }
  };

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "flex-end", mb: 1 }}>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => { setForm({ name: "", key: "", description: "" }); setDialog("create"); }}>
          Создать
        </Button>
      </Box>
      {error && <Alert severity="error" sx={{ mb: 1 }}>{error}</Alert>}
      <TableContainer component={Paper}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>ID</TableCell>
              <TableCell>Название</TableCell>
              <TableCell>Ключ</TableCell>
              <TableCell>Описание</TableCell>
              <TableCell align="center">Действия</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {items.map((t) => (
              <TableRow key={t.id} hover>
                <TableCell>{t.id}</TableCell>
                <TableCell>{t.name}</TableCell>
                <TableCell><code>{t.key}</code></TableCell>
                <TableCell>{t.description}</TableCell>
                <TableCell align="center">
                  <IconButton size="small" onClick={() => { setEditing(t); setForm({ name: t.name, key: t.key, description: t.description }); setDialog("edit"); }}>
                    <EditIcon fontSize="small" />
                  </IconButton>
                  <IconButton size="small" onClick={() => { setEditing(t); setDialog("delete"); }}>
                    <DeleteIcon fontSize="small" />
                  </IconButton>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog open={dialog === "create"} onClose={() => setDialog(null)} maxWidth="sm" fullWidth>
        <DialogTitle>Новый тип угрозы</DialogTitle>
        <DialogContent>
          <TextField fullWidth label="Название" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} sx={{ mt: 1, mb: 2 }} />
          <TextField fullWidth label="Ключ (англ)" value={form.key} onChange={(e) => setForm({ ...form, key: e.target.value })} sx={{ mb: 2 }} />
          <TextField fullWidth label="Описание" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} multiline rows={2} />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialog(null)}>Отмена</Button>
          <Button variant="contained" onClick={handleCreate}>Создать</Button>
        </DialogActions>
      </Dialog>

      <Dialog open={dialog === "edit"} onClose={() => setDialog(null)} maxWidth="sm" fullWidth>
        <DialogTitle>Редактировать: {editing?.key}</DialogTitle>
        <DialogContent>
          <TextField fullWidth label="Название" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} sx={{ mt: 1, mb: 2 }} />
          <TextField fullWidth label="Описание" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} multiline rows={2} />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialog(null)}>Отмена</Button>
          <Button variant="contained" onClick={handleEdit}>Сохранить</Button>
        </DialogActions>
      </Dialog>

      <Dialog open={dialog === "delete"} onClose={() => setDialog(null)}>
        <DialogTitle>Удалить тип угрозы?</DialogTitle>
        <DialogContent><Typography>«{editing?.name}» будет удалён со всеми связанными шаблонами.</Typography></DialogContent>
        <DialogActions>
          <Button onClick={() => setDialog(null)}>Отмена</Button>
          <Button color="error" onClick={handleDelete}>Удалить</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

function LinesEditor({
  value,
  onChange,
  label,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  label: string;
  placeholder?: string;
}) {
  const lines = useMemo(() => (value ? value.split("\n") : [""]), [value]);
  const set = (i: number, v: string) => onChange(lines.map((ln, idx) => (idx === i ? v : ln)).join("\n"));
  const add = (i: number) => onChange([...lines.slice(0, i + 1), "", ...lines.slice(i + 1)].join("\n"));
  const remove = (i: number) => onChange(lines.filter((_, idx) => idx !== i).join("\n"));
  const move = (i: number, dir: -1 | 1) => {
    const j = i + dir;
    if (j < 0 || j >= lines.length) return;
    const next = [...lines];
    [next[i], next[j]] = [next[j], next[i]];
    onChange(next.join("\n"));
  };
  return (
    <Box sx={{ mb: 2 }}>
      <Typography variant="caption" sx={{ display: "block", mb: 0.5, color: "text.secondary" }}>{label}</Typography>
      {lines.map((ln, i) => (
        <Box key={i} sx={{ display: "flex", alignItems: "flex-start", gap: 0.5, mb: 0.5 }}>
          <TextField
            size="small"
            fullWidth
            multiline
            minRows={1}
            value={ln}
            placeholder={placeholder}
            onChange={(e) => set(i, e.target.value)}
          />
          <IconButton size="small" title="Выше" disabled={i === 0} onClick={() => move(i, -1)}>
            <ArrowUpwardIcon fontSize="small" />
          </IconButton>
          <IconButton size="small" title="Ниже" disabled={i === lines.length - 1} onClick={() => move(i, 1)}>
            <ArrowDownwardIcon fontSize="small" />
          </IconButton>
          <IconButton size="small" title="Удалить" onClick={() => remove(i)}>
            <RemoveCircleOutlineIcon fontSize="small" />
          </IconButton>
        </Box>
      ))}
      <Button size="small" startIcon={<AddIcon />} onClick={() => add(lines.length - 1)}>
        Добавить строку
      </Button>
    </Box>
  );
}

function MeasureTemplatesTab({ items, threatTypes, onChanged }: { items: MeasureTemplateResponse[]; threatTypes: ThreatTypeResponse[]; onChanged: () => void }) {
  const [dialog, setDialog] = useState<"create" | "edit" | "delete" | null>(null);
  const [editing, setEditing] = useState<MeasureTemplateResponse | null>(null);
  const [form, setForm] = useState({ name: "", threat_type_id: null as number | null, measures: "", is_default: false });
  const [error, setError] = useState("");

  const handleSave = async () => {
    setError("");
    try {
      if (dialog === "create") {
        await templatesApi.createMeasureTemplate(form);
      } else if (dialog === "edit" && editing) {
        await templatesApi.updateMeasureTemplate(editing.id, { ...form, threat_type_id: form.threat_type_id ?? undefined });
      }
      setDialog(null);
      onChanged();
    } catch (err: any) {
      setError(err.response?.data?.detail || "Ошибка");
    }
  };

  const handleDelete = async () => {
    if (!editing) return;
    try {
      await templatesApi.deleteMeasureTemplate(editing.id);
      setDialog(null);
      setEditing(null);
      onChanged();
    } catch (err: any) {
      setError(err.response?.data?.detail || "Ошибка");
    }
  };

  const typeName = (id: number | null) => threatTypes.find(t => t.id === id)?.name || "—";

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "flex-end", mb: 1 }}>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => { setForm({ name: "", threat_type_id: null, measures: "", is_default: false }); setDialog("create"); }}>
          Создать
        </Button>
      </Box>
      {error && <Alert severity="error" sx={{ mb: 1 }}>{error}</Alert>}
      <TableContainer component={Paper}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Название</TableCell>
              <TableCell>Тип угрозы</TableCell>
              <TableCell>По умолч.</TableCell>
              <TableCell>Мер</TableCell>
              <TableCell align="center">Действия</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {items.map((t) => (
              <TableRow key={t.id} hover>
                <TableCell>{t.name}</TableCell>
                <TableCell>{typeName(t.threat_type_id)}</TableCell>
                <TableCell>{t.is_default ? "Да" : "—"}</TableCell>
                <TableCell>{t.measures.split("\n").filter(Boolean).length}</TableCell>
                <TableCell align="center">
                  <IconButton size="small" onClick={() => { setEditing(t); setForm({ name: t.name, threat_type_id: t.threat_type_id, measures: t.measures, is_default: t.is_default }); setDialog("edit"); }}>
                    <EditIcon fontSize="small" />
                  </IconButton>
                  <IconButton size="small" onClick={() => { setEditing(t); setDialog("delete"); }}>
                    <DeleteIcon fontSize="small" />
                  </IconButton>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog open={dialog === "create" || dialog === "edit"} onClose={() => setDialog(null)} maxWidth="md" fullWidth>
        <DialogTitle>{dialog === "create" ? "Новый блок мер" : "Редактировать блок мер"}</DialogTitle>
        <DialogContent>
          <TextField fullWidth label="Название" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} sx={{ mt: 1, mb: 2 }} />
          <TextField
            fullWidth
            select
            label="Тип угрозы"
            value={form.threat_type_id ?? ""}
            onChange={(e) => setForm({ ...form, threat_type_id: e.target.value ? Number(e.target.value) : null })}
            sx={{ mb: 2 }}
            slotProps={{ select: { native: true } }}
          >
            <option value="">—</option>
            {threatTypes.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </TextField>
          <LinesEditor
            value={form.measures}
            onChange={(v) => setForm({ ...form, measures: v })}
            label="Меры (по одной на строку)"
            placeholder="Например: …к указанным адресатам"
          />
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <Switch checked={form.is_default} onChange={(e) => setForm({ ...form, is_default: e.target.checked })} />
            <Typography>По умолчанию для этого типа</Typography>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialog(null)}>Отмена</Button>
          <Button variant="contained" onClick={handleSave}>Сохранить</Button>
        </DialogActions>
      </Dialog>

      <Dialog open={dialog === "delete"} onClose={() => setDialog(null)}>
        <DialogTitle>Удалить блок мер?</DialogTitle>
        <DialogContent><Typography>«{editing?.name}» будет удалён.</Typography></DialogContent>
        <DialogActions>
          <Button onClick={() => setDialog(null)}>Отмена</Button>
          <Button color="error" onClick={handleDelete}>Удалить</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

function VulnTemplatesTab({ items, onChanged }: { items: VulnMeasureTemplateResponse[]; onChanged: () => void }) {
  const [dialog, setDialog] = useState<"create" | "edit" | "delete" | null>(null);
  const [editing, setEditing] = useState<VulnMeasureTemplateResponse | null>(null);
  const [form, setForm] = useState({ name: "", action_type: "update", content: "", is_default: false });
  const [error, setError] = useState("");

  const handleSave = async () => {
    setError("");
    try {
      if (dialog === "create") {
        await templatesApi.createVulnTemplate(form);
      } else if (dialog === "edit" && editing) {
        await templatesApi.updateVulnTemplate(editing.id, form);
      }
      setDialog(null);
      onChanged();
    } catch (err: any) {
      setError(err.response?.data?.detail || "Ошибка");
    }
  };

  const handleDelete = async () => {
    if (!editing) return;
    try {
      await templatesApi.deleteVulnTemplate(editing.id);
      setDialog(null);
      setEditing(null);
      onChanged();
    } catch (err: any) {
      setError(err.response?.data?.detail || "Ошибка");
    }
  };

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "flex-end", mb: 1 }}>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => { setForm({ name: "", action_type: "update", content: "", is_default: false }); setDialog("create"); }}>
          Создать
        </Button>
      </Box>
      {error && <Alert severity="error" sx={{ mb: 1 }}>{error}</Alert>}
      <TableContainer component={Paper}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Название</TableCell>
              <TableCell>Действие</TableCell>
              <TableCell>По умолч.</TableCell>
              <TableCell align="center">Действия</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {items.map((t) => (
              <TableRow key={t.id} hover>
                <TableCell>{t.name}</TableCell>
                <TableCell><code>{t.action_type}</code></TableCell>
                <TableCell>{t.is_default ? "Да" : "—"}</TableCell>
                <TableCell align="center">
                  <IconButton size="small" onClick={() => { setEditing(t); setForm({ name: t.name, action_type: t.action_type, content: t.content, is_default: t.is_default }); setDialog("edit"); }}>
                    <EditIcon fontSize="small" />
                  </IconButton>
                  <IconButton size="small" onClick={() => { setEditing(t); setDialog("delete"); }}>
                    <DeleteIcon fontSize="small" />
                  </IconButton>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog open={dialog === "create" || dialog === "edit"} onClose={() => setDialog(null)} maxWidth="md" fullWidth>
        <DialogTitle>{dialog === "create" ? "Новый шаблон уязвимости" : "Редактировать шаблон"}</DialogTitle>
        <DialogContent>
          <TextField fullWidth label="Название" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} sx={{ mt: 1, mb: 2 }} />
          <TextField
            fullWidth
            select
            label="Действие"
            value={form.action_type}
            onChange={(e) => setForm({ ...form, action_type: e.target.value })}
            sx={{ mb: 2 }}
            slotProps={{ select: { native: true } }}
          >
            {["update", "compensate", "skip", "monitor", "isolate", "patch", "restrict", "audit"].map((a) => (
              <option key={a} value={a}>{a}</option>
            ))}
          </TextField>
          <TextField fullWidth label="Текст шаблона ({software} = название ПО)" value={form.content} onChange={(e) => setForm({ ...form, content: e.target.value })} multiline rows={3} sx={{ mb: 2 }} />
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <Switch checked={form.is_default} onChange={(e) => setForm({ ...form, is_default: e.target.checked })} />
            <Typography>По умолчанию</Typography>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialog(null)}>Отмена</Button>
          <Button variant="contained" onClick={handleSave}>Сохранить</Button>
        </DialogActions>
      </Dialog>

      <Dialog open={dialog === "delete"} onClose={() => setDialog(null)}>
        <DialogTitle>Удалить шаблон?</DialogTitle>
        <DialogContent><Typography>«{editing?.name}» будет удалён.</Typography></DialogContent>
        <DialogActions>
          <Button onClick={() => setDialog(null)}>Отмена</Button>
          <Button color="error" onClick={handleDelete}>Удалить</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}