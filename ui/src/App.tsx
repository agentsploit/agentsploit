import { Route, Routes } from "react-router-dom";

import Layout from "@/components/Layout";
import RequireAuth from "@/components/RequireAuth";
import SessionsList from "@/pages/SessionsList";
import SessionDetail from "@/pages/SessionDetail";
import JobsPage from "@/pages/JobsPage";
import Login from "@/pages/Login";

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route index element={<SessionsList />} />
        <Route path="sessions/:sessionId" element={<SessionDetail />} />
        <Route path="jobs" element={<JobsPage />} />
      </Route>
    </Routes>
  );
}
