import React, { useState, useEffect } from "react";
import { Sidebar } from "./components/layout/Sidebar";
import { TopBar } from "./components/layout/TopBar";
import { JobTray } from "./components/layout/JobTray";
import { OverviewPage } from "./pages/OverviewPage";
import { ProgramsPage } from "./pages/ProgramsPage";
import { AssetsPage } from "./pages/AssetsPage";
import { JobsPage } from "./pages/JobsPage";
import { TrafficPage } from "./pages/TrafficPage";
import { TestPlannerPage } from "./pages/TestPlannerPage";
import { FindingsPage } from "./pages/FindingsPage";
import { ReportsPage } from "./pages/ReportsPage";
import { ToolchainPage } from "./pages/ToolchainPage";
import { SettingsPage } from "./pages/SettingsPage";
import { Program, Asset, Finding, Job, ipc } from "./services/ipc";

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<string>("overview");
  const [programs, setPrograms] = useState<Program[]>([]);
  const [selectedProgramId, setSelectedProgramId] = useState<string>("");
  const [assets, setAssets] = useState<Asset[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [searchQuery, setSearchQuery] = useState<string>("");

  useEffect(() => {
    loadPrograms();
  }, []);

  useEffect(() => {
    if (selectedProgramId) {
      loadProgramData(selectedProgramId);
    }
  }, [selectedProgramId]);

  const loadPrograms = async () => {
    const list = await ipc.sendCommand<Program[]>("programs.list");
    setPrograms(list);
    if (list.length > 0 && !selectedProgramId) {
      setSelectedProgramId(list[0].id);
    }
  };

  const loadProgramData = async (pid: string) => {
    const assetList = await ipc.sendCommand<Asset[]>("assets.list", { program_id: pid });
    setAssets(assetList);

    const findingList = await ipc.sendCommand<Finding[]>("findings.list", { program_id: pid });
    setFindings(findingList);

    const jobList = await ipc.sendCommand<Job[]>("jobs.list", { program_id: pid });
    setJobs(jobList);
  };

  const handleCancelJob = async (jobId: string) => {
    await ipc.sendCommand("jobs.cancel", { job_id: jobId });
    if (selectedProgramId) loadProgramData(selectedProgramId);
  };

  const activeProgram = programs.find((p) => p.id === selectedProgramId);
  const activeJobCount = jobs.filter((j) => j.status === "running" || j.status === "validating_scope").length;

  return (
    <div className="app-container">
      <Sidebar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        programs={programs}
        selectedProgramId={selectedProgramId}
        onSelectProgram={setSelectedProgramId}
      />
      <div className="main-content">
        <TopBar
          activeProgram={activeProgram}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          activeJobCount={activeJobCount}
        />
        {currentTab === "overview" && (
          <OverviewPage
            program={activeProgram}
            assets={assets}
            findings={findings}
            jobs={jobs}
            onNavigate={setCurrentTab}
          />
        )}
        {currentTab === "programs" && (
          <ProgramsPage
            programs={programs}
            activeProgramId={selectedProgramId}
            onRefreshPrograms={loadPrograms}
          />
        )}
        {currentTab === "assets" && (
          <AssetsPage
            program={activeProgram}
            assets={assets}
          />
        )}
        {currentTab === "jobs" && (
          <JobsPage
            program={activeProgram}
            jobs={jobs}
            onRefreshJobs={() => selectedProgramId && loadProgramData(selectedProgramId)}
            onCancelJob={handleCancelJob}
          />
        )}
        {currentTab === "traffic" && (
          <TrafficPage program={activeProgram} />
        )}
        {currentTab === "planner" && (
          <TestPlannerPage program={activeProgram} />
        )}
        {currentTab === "findings" && (
          <FindingsPage
            program={activeProgram}
            findings={findings}
            onRefreshFindings={() => selectedProgramId && loadProgramData(selectedProgramId)}
          />
        )}
        {currentTab === "reports" && (
          <ReportsPage
            program={activeProgram}
            findings={findings}
            assets={assets}
          />
        )}
        {currentTab === "toolchain" && (
          <ToolchainPage />
        )}
        {currentTab === "settings" && (
          <SettingsPage />
        )}
        <JobTray jobs={jobs} onCancelJob={handleCancelJob} />
      </div>
    </div>
  );
};
