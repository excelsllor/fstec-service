import { useEffect, useState } from "react";
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
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  IconButton,
  Alert,
  Snackbar,
  FormControlLabel,
  Switch,
  CircularProgress,
} from "@mui/material";
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
} from "@mui/icons-material";
import { usersApi, type UserResponse } from "../../api/client";
import { useAuthStore } from "../../store/auth";

export default function Users() {
  const currentUser = useAuthStore((s) => s.user);
  const [users, setUsers] = useState<UserResponse[]>([]);
  const [dialog, setDialog] = useState<"create" | "edit" | "delete" | null>(null);
  const [editing, setEditing] = useState<UserResponse | null>(null);
  const [form, setForm] = useState({ username: "", password: "", role: "user", full_name: "", is_active: true });
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const { data } = await usersApi.list();
      setUsers(data);
      setError("");
    } catch (err: any) {
      setError(err.response?.data?.detail || (err as Error)?.message || "Не удалось загрузить пользователей");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const handleCreate = async () => {
    setError("");
    try {
      await usersApi.create({ username: form.username, password: form.password,
                              role: form.role, full_name: form.full_name });
      setDialog(null);
      setForm({ username: "", password: "", role: "user", full_name: "", is_active: true });
      load();
    } catch (err: any) {
      setError(err.response?.data?.detail || "Ошибка");
    }
  };

  const handleEdit = async () => {
    if (!editing) return;
    setError("");
    try {
      await usersApi.update(editing.id, {
        full_name: form.full_name,
        password: form.password || undefined,
        role: form.role || undefined,
        is_active: form.is_active,
      });
      setDialog(null);
      load();
    } catch (err: any) {
      setError(err.response?.data?.detail || "Ошибка");
    }
  };

  const handleDelete = async () => {
    if (!editing) return;
    setError("");
    try {
      const { data } = await usersApi.delete(editing.id);
      setDialog(null);
      setEditing(null);
      if (data?.deactivated) {
        setNotice(data.detail || "У пользователя есть письма — учётная запись отключена");
      }
      load();
    } catch (err: any) {
      setError(err.response?.data?.detail || "Ошибка");
      setDialog(null);
    }
  };

  const openEdit = (u: UserResponse) => {
    setEditing(u);
    setForm({ username: u.username, password: "", role: u.role, full_name: u.full_name, is_active: u.is_active });
    setDialog("edit");
  };

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
        <Typography variant="h5">Пользователи</Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => { setForm({ username: "", password: "", role: "user", full_name: "", is_active: true }); setDialog("create"); }}
        >
          Создать
        </Button>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError("")}>{error}</Alert>}
      <Snackbar open={Boolean(notice)} autoHideDuration={6000} onClose={() => setNotice("")}
                message={notice} anchorOrigin={{ vertical: "bottom", horizontal: "center" }} />

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>ID</TableCell>
              <TableCell>Имя пользователя</TableCell>
              <TableCell>Полное имя</TableCell>
              <TableCell>Роль</TableCell>
              <TableCell>Статус</TableCell>
              <TableCell>Создан</TableCell>
              <TableCell align="center">Действия</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading && (
              <TableRow>
                <TableCell colSpan={7} align="center"><CircularProgress size={24} sx={{ my: 1 }} /></TableCell>
              </TableRow>
            )}
            {!loading && users.length === 0 && !error && (
              <TableRow>
                <TableCell colSpan={7} align="center">Нет пользователей</TableCell>
              </TableRow>
            )}
            {users.map((u) => (
              <TableRow key={u.id} hover>
                <TableCell>{u.id}</TableCell>
                <TableCell>{u.username}{u.id === currentUser?.id ? " (вы)" : ""}</TableCell>
                <TableCell>{u.full_name || "—"}</TableCell>
                <TableCell>
                  <Chip
                    label={u.role === "admin" ? "Администратор" : "Пользователь"}
                    color={u.role === "admin" ? "error" : "default"}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Chip
                    label={u.is_active ? "Активен" : "Отключён"}
                    color={u.is_active ? "success" : "default"}
                    size="small"
                  />
                </TableCell>
                <TableCell>{u.created_at ? new Date(u.created_at).toLocaleDateString("ru-RU") : "—"}</TableCell>
                <TableCell align="center">
                  <IconButton size="small" onClick={() => openEdit(u)}>
                    <EditIcon fontSize="small" />
                  </IconButton>
                  <IconButton size="small" disabled={u.id === currentUser?.id}
                              onClick={() => { setEditing(u); setDialog("delete"); }}>
                    <DeleteIcon fontSize="small" />
                  </IconButton>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog open={dialog === "create"} onClose={() => setDialog(null)} maxWidth="sm" fullWidth>
        <DialogTitle>Новый пользователь</DialogTitle>
        <DialogContent>
          <TextField fullWidth label="Имя пользователя" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} sx={{ mt: 1, mb: 2 }} />
          <TextField fullWidth label="Полное имя" value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} sx={{ mb: 2 }} />
          <TextField fullWidth label="Пароль" type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} sx={{ mb: 2 }} />
          <FormControl fullWidth>
            <InputLabel>Роль</InputLabel>
            <Select value={form.role} label="Роль" onChange={(e) => setForm({ ...form, role: e.target.value })}>
              <MenuItem value="user">Пользователь</MenuItem>
              <MenuItem value="admin">Администратор</MenuItem>
            </Select>
          </FormControl>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialog(null)}>Отмена</Button>
          <Button variant="contained" onClick={handleCreate}>Создать</Button>
        </DialogActions>
      </Dialog>

      <Dialog open={dialog === "edit"} onClose={() => setDialog(null)} maxWidth="sm" fullWidth>
        <DialogTitle>Редактировать: {editing?.username}</DialogTitle>
        <DialogContent>
          <TextField fullWidth label="Полное имя" value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} sx={{ mt: 1, mb: 2 }} />
          <TextField fullWidth label="Новый пароль (пусто = без изменений)" type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} sx={{ mb: 2 }} />
          <FormControl fullWidth>
            <InputLabel>Роль</InputLabel>
            <Select value={form.role} label="Роль" onChange={(e) => setForm({ ...form, role: e.target.value })}>
              <MenuItem value="user">Пользователь</MenuItem>
              <MenuItem value="admin">Администратор</MenuItem>
            </Select>
          </FormControl>
          <FormControlLabel
            sx={{ mt: 2 }}
            control={<Switch checked={form.is_active}
                             onChange={(e) => setForm({ ...form, is_active: e.target.checked })}
                             disabled={editing?.id === currentUser?.id} />}
            label="Учётная запись активна"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialog(null)}>Отмена</Button>
          <Button variant="contained" onClick={handleEdit}>Сохранить</Button>
        </DialogActions>
      </Dialog>

      <Dialog open={dialog === "delete"} onClose={() => setDialog(null)}>
        <DialogTitle>Удалить пользователя?</DialogTitle>
        <DialogContent>
          <Typography>Пользователь «{editing?.username}» будет удалён.</Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialog(null)}>Отмена</Button>
          <Button color="error" onClick={handleDelete}>Удалить</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
