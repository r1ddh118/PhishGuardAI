import { useState } from "react";
import { analyzeMessage, analyzeBatch } from "../lib/ai-engine";
import { Button } from "../components/ui/button";
import { Textarea } from "../components/ui/textarea";
import { Card } from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import { Progress } from "../components/ui/progress";
import { toast } from "sonner";

type ScanMode = "single" | "batch";

export default function ThreatScanConsole() {

  const [mode, setMode] = useState<ScanMode>("single");
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);

  const [result, setResult] = useState<any>(null);
  const [batchResult, setBatchResult] = useState<any>(null);

  async function runSingleScan() {
    if (!message.trim()) {
      toast.error("Enter a message to scan");
      return;
    }

    try {
      setLoading(true);
      setResult(null);

      const response = await analyzeMessage(message);
      setResult(response);

    } catch (err) {
      toast.error("Scan failed");
    } finally {
      setLoading(false);
    }
  }

  async function runBatchScan() {

    if (messages.length === 0) {
      toast.error("Add messages first");
      return;
    }

    try {
      setLoading(true);
      setBatchResult(null);

      const res = await analyzeBatch(messages);
      setBatchResult(res);

    } catch (err) {
      toast.error("Batch scan failed");
    } finally {
      setLoading(false);
    }
  }

  function addMessage() {
    setMessages([...messages, ""]);
  }

  function updateMessage(index: number, value: string) {
    const copy = [...messages];
    copy[index] = value;
    setMessages(copy);
  }

  function removeMessage(index: number) {
    const copy = messages.filter((_, i) => i !== index);
    setMessages(copy);
  }

  function clearSingle() {
    setMessage("");
    setResult(null);
  }

  function riskColor(level: string) {
    if (level === "low") return "bg-green-500";
    if (level === "medium") return "bg-yellow-500";
    if (level === "high") return "bg-orange-500";
    return "bg-red-500";
  }

  function verdictColor(verdict: string) {
    if (verdict === "safe") return "text-green-500";
    if (verdict === "suspicious") return "text-yellow-500";
    return "text-red-500";
  }

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-6">

      <h1 className="text-2xl font-bold">
        Threat Scanner
      </h1>

      <div className="flex gap-4">

        <Button
          variant={mode === "single" ? "default" : "outline"}
          onClick={() => setMode("single")}
        >
          Single Scan
        </Button>

        <Button
          variant={mode === "batch" ? "default" : "outline"}
          onClick={() => setMode("batch")}
        >
          Batch Scan
        </Button>

      </div>

      {mode === "single" && (

        <Card className="p-6 space-y-4">

          <Textarea
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="Paste email, SMS, or chat message..."
            className="min-h-[200px]"
          />

          <div className="flex gap-3">

            <Button
              onClick={runSingleScan}
              disabled={loading}
            >
              {loading ? "Scanning..." : "Scan Message"}
            </Button>

            <Button
              variant="outline"
              onClick={clearSingle}
            >
              Clear
            </Button>

          </div>

        </Card>
      )}

      {mode === "batch" && (

        <Card className="p-6 space-y-4">

          {messages.map((m, i) => (
            <div key={i} className="flex gap-2">

              <input
                value={m}
                onChange={(e) => updateMessage(i, e.target.value)}
                className="flex-1 border rounded px-2 py-1"
                placeholder={`Message ${i + 1}`}
              />

              <Button
                variant="outline"
                onClick={() => removeMessage(i)}
              >
                Remove
              </Button>

            </div>
          ))}

          <div className="flex gap-3">

            <Button
              variant="outline"
              onClick={addMessage}
            >
              Add Message
            </Button>

            <Button
              onClick={runBatchScan}
              disabled={loading}
            >
              {loading ? "Scanning..." : "Run Batch Scan"}
            </Button>

          </div>

        </Card>
      )}

      {result && mode === "single" && (

        <Card className="p-6 space-y-5">

          <div>

            <h2 className="text-lg font-semibold">
              Verdict
            </h2>

            <p className={`text-xl font-bold ${verdictColor(result.prediction)}`}>
              {result.prediction.toUpperCase()}
            </p>

          </div>

          <div>

            <h3 className="text-sm text-zinc-500 mb-1">
              Confidence
            </h3>

            <Progress value={result.confidence * 100} />

            <p className="text-sm mt-1">
              {(result.confidence * 100).toFixed(2)}%
            </p>

          </div>

          <div>

            <h3 className="text-sm text-zinc-500 mb-1">
              Risk Level
            </h3>

            <Badge className={riskColor(result.riskLevel)}>
              {result.riskLevel}
            </Badge>

          </div>

          <div>

            <h3 className="text-sm text-zinc-500 mb-1">
              Explanation
            </h3>

            <p className="text-sm">
              {result.explanation}
            </p>

          </div>

        </Card>

      )}

      {batchResult && mode === "batch" && (

        <Card className="p-6 space-y-4">

          <h2 className="font-semibold">
            Batch Results ({batchResult.total_scanned})
          </h2>

          {batchResult.batch_results.map((r: any, i: number) => (

            <div
              key={i}
              className="border p-3 rounded flex justify-between"
            >

              <span className="text-sm font-mono">
                {r.text_preview}
              </span>

              <div className="flex gap-3 items-center">

                <Badge className={r.is_phishing ? "bg-red-500" : "bg-green-500"}>
                  {r.is_phishing ? "Phishing" : "Safe"}
                </Badge>

                <span className="text-sm">
                  {(r.confidence * 100).toFixed(1)}%
                </span>

              </div>

            </div>

          ))}

        </Card>

      )}

    </div>
  );
}
