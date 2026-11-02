import { useEffect, useState } from "react";
import { Outlet, useNavigate, useLocation } from "react-router-dom";
import {
  AppBar,
  Toolbar,
  Typography,
  Drawer,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Box,
  IconButton,
  Avatar,
  Menu,
  MenuItem,
  Divider,
  useMediaQuery,
  useTheme,
  Snackbar,
  Alert,
} from "@mui/material";
import {
  Dashboard as DashboardIcon,
  Upload as UploadIcon,
  Mail as MailIcon,
  People as PeopleIcon,
  Logout as LogoutIcon,
  Description as TemplateIcon,
  FactCheck as DecisionIcon,
  History as AuditIcon,
  MonitorHeart as DebugIcon,
  Menu as MenuIcon,
} from "@mui/icons-material";
import { useAuthStore } from "../store/auth";

const drawerWidth = 240;

export default function Layout() {
  const { user, logout } = useAuthStore();
  const navigate = useNavigate();
  const location = useLocation();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [apiError, setApiError] = useState("");
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  useEffect(() => {
    const onError = (event: Event) => {
      const detail = (event as CustomEvent).detail;
      setApiError(typeof detail === "string" && detail ? detail : "Ошибка запроса");
    };
    window.addEventListener("fstec-api-error", onError as EventListener);
    return () => window.removeEventListener("fstec-api-error", onError as EventListener);
  }, []);

  const menuItems = [
    { text: "Панель", icon: <DashboardIcon />, path: "/", roles: ["admin", "user"] },
    { text: "Загрузить письмо", icon: <UploadIcon />, path: "/upload", roles: ["admin", "user"] },
    { text: "Письма", icon: <MailIcon />, path: "/letters", roles: ["admin", "user"] },
    { text: "Шаблоны", icon: <TemplateIcon />, path: "/admin/templates", roles: ["admin"] },
    { text: "Меры на рассмотрении", icon: <DecisionIcon />, path: "/admin/measures", roles: ["admin"] },
    { text: "Пользователи", icon: <PeopleIcon />, path: "/admin/users", roles: ["admin"] },
    { text: "Аудит", icon: <AuditIcon />, path: "/audit", roles: ["admin"] },
    { text: "Отладка", icon: <DebugIcon />, path: "/debug", roles: ["admin"] },
  ];

  const visibleItems = menuItems.filter((item) => user && item.roles.includes(user.role));

  return (
    <Box sx={{ display: "flex" }}>
      <AppBar position="fixed" sx={{ zIndex: (theme) => theme.zIndex.drawer + 1 }}>
        <Toolbar>
          {isMobile && (
            <IconButton
              edge="start"
              color="inherit"
              aria-label="Открыть меню"
              onClick={() => setMobileOpen(true)}
              sx={{ mr: 1 }}
            >
              <MenuIcon />
            </IconButton>
          )}
          <Box sx={{ flexGrow: 1 }} />
          <IconButton aria-label="Меню пользователя" onClick={(e) => setAnchorEl(e.currentTarget)} color="inherit">
            <Avatar sx={{ width: 32, height: 32, bgcolor: "secondary.main", fontSize: 14 }}>
              {user?.username?.[0]?.toUpperCase() || "U"}
            </Avatar>
          </IconButton>
          <Menu
            anchorEl={anchorEl}
            open={Boolean(anchorEl)}
            onClose={() => setAnchorEl(null)}
          >
            <MenuItem disabled>
              <Box>
                <Typography variant="body2" sx={{ fontWeight: "bold" }}>{user?.full_name || user?.username}</Typography>
                <Typography variant="caption" color="text.secondary">
                  {user?.role === "admin" ? "Администратор" : "Пользователь"}
                </Typography>
              </Box>
            </MenuItem>
            <Divider />
            <MenuItem onClick={() => { logout(); navigate("/login"); }}>
              <ListItemIcon><LogoutIcon fontSize="small" /></ListItemIcon>
              Выйти
            </MenuItem>
          </Menu>
        </Toolbar>
      </AppBar>

      <Drawer
        variant={isMobile ? "temporary" : "permanent"}
        open={!isMobile || mobileOpen}
        onClose={() => setMobileOpen(false)}
        ModalProps={{ keepMounted: true }}
        sx={{
          width: drawerWidth,
          flexShrink: 0,
          "& .MuiDrawer-paper": { width: drawerWidth, boxSizing: "border-box" },
        }}
      >
        <Toolbar />
        <Box sx={{ overflow: "auto" }}>
          <List>
            {visibleItems.map((item) => (
              <ListItem key={item.path} disablePadding>
                <ListItemButton
                  selected={location.pathname === item.path}
                  onClick={() => {
                    navigate(item.path);
                    if (isMobile) setMobileOpen(false);
                  }}
                >
                  <ListItemIcon>{item.icon}</ListItemIcon>
                  <ListItemText primary={item.text} />
                </ListItemButton>
              </ListItem>
            ))}
          </List>
        </Box>
      </Drawer>

      <Box component="main" sx={{ flexGrow: 1, minWidth: 0, p: { xs: 1.5, md: 3 } }}>
        <Toolbar />
        <Outlet />
      </Box>

      <Snackbar open={!!apiError} autoHideDuration={5000} onClose={() => setApiError("")}
                anchorOrigin={{ vertical: "bottom", horizontal: "center" }}>
        <Alert severity="error" onClose={() => setApiError("")} variant="filled">
          {apiError}
        </Alert>
      </Snackbar>
    </Box>
  );
}
