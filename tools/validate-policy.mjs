// Validiert EDEP-Richtlinien gegen schema/edep-policy.schema.json und prüft,
// dass typische Verstöße abgelehnt werden.
//
//   npm install --no-save ajv@8 yaml@2
//   node tools/validate-policy.mjs examples/policy.example.yaml [weitere.yaml ...]

import Ajv2020 from "ajv/dist/2020.js";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import YAML from "yaml";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const schema = JSON.parse(
  readFileSync(join(root, "schema/edep-policy.schema.json"), "utf8"),
);
// strictRequired meldet "required" in if/then-Zweigen; das ist gültiges JSON Schema.
const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
});
const validate = ajv.compile(schema);

let failed = 0;
const files = process.argv.slice(2);
if (files.length === 0) {
  console.error("Aufruf: node tools/validate-policy.mjs <policy.yaml> ...");
  process.exit(2);
}

for (const file of files) {
  const doc = YAML.parse(readFileSync(file, "utf8"));
  if (validate(doc)) {
    console.log(`gültig: ${file}`);
  } else {
    failed++;
    console.log(`UNGÜLTIG: ${file}`);
    for (const e of validate.errors)
      console.log(`  ${e.instancePath || "/"} ${e.message}`);
  }
}

// Negativtests: Diese Verstöße muss das Schema ablehnen.
const base = YAML.parse(readFileSync(files[0], "utf8"));
const negatives = [
  [
    "enforce mit ausgehend allow (EDEP-NET-03)",
    (d) => {
      d.mode = "enforce";
      d.network.outbound_default = "allow";
    },
  ],
  [
    "nur Pfad als Identität (EDEP-ID-03)",
    (d) => {
      d.apps[0].identity = { path: "C:/x.exe" };
    },
  ],
  [
    "L3 ohne isolation (EDEP-ISO-01)",
    (d) => {
      d.level = "L3";
      delete d.isolation;
    },
  ],
  [
    "Modell als Isolationsauslöser (EDEP-ISO-03)",
    (d) => {
      d.level = "L3";
      d.isolation = { triggers: [{ type: "model" }] };
    },
  ],
  [
    "Modell mit Durchsetzungsrolle (EDEP-INF-02)",
    (d) => {
      d.inference = { enabled: true, role: "enforce" };
    },
  ],
  [
    "Wartungsmodus über 30 min (EDEP-OPS-03)",
    (d) => {
      d.maintenance = { max_minutes: 120 };
    },
  ],
  [
    "unbekanntes Feld",
    (d) => {
      d.backdoor = true;
    },
  ],
];
for (const [name, mutate] of negatives) {
  const d = structuredClone(base);
  mutate(d);
  if (validate(d)) {
    failed++;
    console.log(`FEHLER: akzeptiert, obwohl ungültig: ${name}`);
  } else {
    console.log(`abgelehnt (korrekt): ${name}`);
  }
}

process.exit(failed ? 1 : 0);
