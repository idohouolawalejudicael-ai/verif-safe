const express = require("express");
const path = require("path");
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public")));

app.post("/api/analyze-url", (req, res) => {
  const raw = String(req.body?.url || "").trim();
  if (!raw) return res.status(400).json({ error: "URL manquante." });

  let u;
  try { u = new URL(raw.startsWith("http") ? raw : "https://" + raw); }
  catch { return res.status(400).json({ error: "URL invalide." }); }

  const signals = [];
  let score = 0;

  if (u.protocol !== "https:") { score += 20; signals.push("Le lien n'utilise pas HTTPS."); }
  if (u.hostname.includes("xn--")) { score += 20; signals.push("Le domaine contient une forme encodée pouvant nécessiter une vérification."); }
  if (u.hostname.split(".").length > 3) { score += 10; signals.push("Le domaine comporte plusieurs sous-domaines."); }
  if (u.href.length > 120) { score += 10; signals.push("L'URL est particulièrement longue."); }

  const level = score >= 40 ? "Élevé" : score >= 20 ? "Vigilance" : "Faible";
  res.json({
    url: u.href,
    domain: u.hostname,
    score,
    level,
    signals: signals.length ? signals : ["Aucun signal technique simple n'a été détecté par cette première analyse."],
    disclaimer: "Analyse indicative basée sur des signaux techniques simples. Elle ne certifie ni l'identité, ni la fiabilité, ni la légalité d'un site."
  });
});

app.listen(PORT, () => console.log(`VÉRIF-SAFE démarré sur le port ${PORT}`));
