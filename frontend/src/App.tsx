import { A2a } from "./pages/A2a";
import { Agents } from "./pages/Agents";
import { Ans } from "./pages/Ans";
import { Approvals } from "./pages/Approvals";
import { Audit } from "./pages/Audit";
import { Identity } from "./pages/Identity";
import { Jit } from "./pages/Jit";
import { Mcp } from "./pages/Mcp";
import { Overview } from "./pages/Overview";
import { Policies } from "./pages/Policies";
import { System } from "./pages/System";
import { Threats } from "./pages/Threats";
import { Workflow } from "./pages/Workflow";
import { Shell, useRoute } from "./shell/Shell";

/**
 * PRECISION Operations Console.
 *
 * Every page reads the live IAM API (and the ANS service) and renders the
 * server's answer, including its refusals. The console decides nothing: it
 * offers actions and shows what the PDP, the Session Authority and the HITL
 * service permitted. There is no client-side permission model to drift.
 */
export default function App() {
  const [route, go] = useRoute();
  const page = (() => {
    switch (route) {
      case "workflow": return <Workflow go={go} />;
      case "agents": return <Agents />;
      case "identity": return <Identity />;
      case "ans": return <Ans />;
      case "policies": return <Policies />;
      case "jit": return <Jit />;
      case "approvals": return <Approvals />;
      case "a2a": return <A2a />;
      case "mcp": return <Mcp />;
      case "threats": return <Threats />;
      case "audit": return <Audit />;
      case "system": return <System />;
      default: return <Overview go={go} />;
    }
  })();
  return <Shell route={route} go={go}><div key={route}>{page}</div></Shell>;
}
