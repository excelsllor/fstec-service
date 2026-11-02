import { useEffect, useState } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { Box, CircularProgress } from "@mui/material";
import { useAuthStore } from "./store/auth";
import Login from "./pages/Login";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Upload from "./pages/Upload";
import LetterList from "./pages/LetterList";
import LetterDetail from "./pages/LetterDetail";
import Users from "./pages/Admin/Users";
import Templates from "./pages/Admin/Templates";
import Measures from "./pages/Admin/Measures";
import Audit from "./pages/Audit";
import Diagnostics from "./pages/Diagnostics";

function ProtectedRoute({ children, requireAdmin }: { children: React.ReactNode; requireAdmin?: boolean }) {
  const { token, user } = useAuthStore();
  if (!token) return <Navigate to="/login" replace />;
  if (requireAdmin && user?.role !== "admin") return <Navigate to="/" replace />;
  return <>{children}</>;
}

export default function App() {
  const { token, checkAuth, checkStatus, initialized } = useAuthStore();
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    const init = async () => {
      if (token) {
        await checkAuth();
      } else {
        await checkStatus();
      }
      setChecking(false);
    };
    init();
  }, []);

  if (checking || !initialized) {
    return (
      <Box sx={{ display: "flex", justifyContent: "center", alignItems: "center", minHeight: "100vh" }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!token) {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    );
  }

  return (
    <Routes>
      <Route path="/login" element={<Navigate to="/" replace />} />
      <Route element={<ProtectedRoute><Layout /></ProtectedRoute>}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/upload" element={<Upload />} />
        <Route path="/letters" element={<LetterList />} />
        <Route path="/letters/:id" element={<LetterDetail />} />
        <Route path="/admin/users" element={<ProtectedRoute requireAdmin><Users /></ProtectedRoute>} />
        <Route path="/admin/templates" element={<ProtectedRoute requireAdmin><Templates /></ProtectedRoute>} />
        <Route path="/admin/measures" element={<ProtectedRoute requireAdmin><Measures /></ProtectedRoute>} />
        <Route path="/audit" element={<ProtectedRoute requireAdmin><Audit /></ProtectedRoute>} />
        <Route path="/debug" element={<ProtectedRoute requireAdmin><Diagnostics /></ProtectedRoute>} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
