import { Route, Routes } from "react-router-dom";

import Layout from "@/components/Layout";
import SessionsList from "@/pages/SessionsList";
import SessionDetail from "@/pages/SessionDetail";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<SessionsList />} />
        <Route path="sessions/:sessionId" element={<SessionDetail />} />
      </Route>
    </Routes>
  );
}
