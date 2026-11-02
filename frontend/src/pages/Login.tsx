import { useEffect, useState } from "react";
import {
  Box,
  Paper,
  TextField,
  Button,
  Typography,
  Alert,
  Container,
  CircularProgress,
  IconButton,
  Tooltip,
} from "@mui/material";
import SecurityIcon from "@mui/icons-material/Security";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import { useAuthStore } from "../store/auth";

export default function Login() {
  const { login, needsSetup, bootstrap } = useAuthStore();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (needsSetup && bootstrap) {
      setUsername((u) => u || bootstrap.username);
    }
  }, [needsSetup, bootstrap]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(username, password);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Ошибка входа");
    } finally {
      setLoading(false);
    }
  };

  const copyBootstrap = async () => {
    if (!bootstrap || !bootstrap.password) return;
    const text = `Логин: ${bootstrap.username}\nПароль: ${bootstrap.password}`;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setError("Не удалось скопировать — скопируйте пароль вручную");
    }
  };

  return (
    <Container maxWidth="sm">
      <Box
        sx={{
          minHeight: "100vh",
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          alignItems: "center",
        }}
      >
        <Paper elevation={3} sx={{ p: 4, width: "100%", maxWidth: 400 }}>
          <Box sx={{ display: "flex", justifyContent: "center", mb: 2 }}>
            <SecurityIcon sx={{ fontSize: 48, color: "primary.main" }} />
          </Box>
          <Typography variant="body2" color="text.secondary" align="center" sx={{ mb: 3 }}>
            Вход в систему
          </Typography>

          {needsSetup && bootstrap && (
            <Paper variant="outlined" sx={{ p: 2, mb: 2, bgcolor: "warning.light" }}>
              <Typography variant="subtitle2" gutterBottom>Первичная инициализация</Typography>
              {bootstrap.password ? (
                <>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    Данные для первого входа:
                  </Typography>
                  <Typography variant="body2">
                    Логин: <strong>{bootstrap.username}</strong>
                  </Typography>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                    <Typography variant="body2">
                      Пароль: <strong>{bootstrap.password}</strong>
                    </Typography>
                    <Tooltip title={copied ? "Скопировано" : "Скопировать"}>
                      <IconButton size="small" onClick={copyBootstrap}>
                        <ContentCopyIcon fontSize="inherit" />
                      </IconButton>
                    </Tooltip>
                  </Box>
                  <Button size="small" sx={{ mt: 1 }} onClick={() => {
                    setUsername(bootstrap.username);
                    setPassword(bootstrap.password || "");
                  }}>
                    Подставить в форму
                  </Button>
                </>
              ) : null}
            </Paper>
          )}

          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}

          <Box component="form" onSubmit={handleSubmit}>
            <TextField
              fullWidth
              label="Имя пользователя"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              margin="normal"
              required
              autoFocus
            />
            <TextField
              fullWidth
              label="Пароль"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              margin="normal"
              required
            />
            <Button
              type="submit"
              fullWidth
              variant="contained"
              sx={{ mt: 3, mb: 2 }}
              disabled={loading}
            >
              {loading ? <CircularProgress size={24} /> : "Войти"}
            </Button>
          </Box>

        </Paper>
      </Box>
    </Container>
  );
}
