const express = require("express");
const fs = require("fs");
const cors = require("cors");

const app = express();
app.use(cors());

const ALERT_FILE = "../alerts.jsonl";

app.get("/alerts", (req, res) => {
  try {
    if (!fs.existsSync(ALERT_FILE)) {
      return res.json([]);
    }

    const raw = fs.readFileSync(ALERT_FILE, "utf-8").trim();

    if (!raw) {
      return res.json([]);
    }

    const alerts = raw
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line));

    res.json(alerts);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to read alerts" });
  }
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
