"use strict";

// ─────────────────────────────────────────────────────────────────────────────
//  data.js
//  Single source of truth.
//  Contains: threat model, 6Vs definitions, and recommendations.
//  Loaded first by index.html — all other scripts depend on this.
// ─────────────────────────────────────────────────────────────────────────────

const LAYERS = ["Ingestion", "Storage", "Processing", "Analysis", "Serving"];

const THREATS = [

  // ── INGESTION ──────────────────────────────────────────────────────────────
  {
    id: "T01",
    layer: "Ingestion",
    threat: "API and Data Injection",
    description: "Malicious payloads pushed through unsanitized ingestion APIs such as Kafka, Flume, and Apache NiFi corrupt the data pipeline from the entry point. Attackers exploit missing schema validation to inject records that poison downstream processing and analytics.",
    cia: ["Integrity"],
    vs: ["Variety", "Velocity"],
    severity: "Critical",
    likelihood: 5,
    impact: 5,
    mitre: "T1190",
    controls: "Enforce strict schema validation at ingestion, deploy an API gateway with WAF rules, apply allowlist-based input sanitization on all ingestion endpoints."
  },
  {
    id: "T02",
    layer: "Ingestion",
    threat: "Man-in-the-Middle Attack",
    description: "Absence of mutual TLS between data producers and ingestion brokers exposes streaming data to interception. An attacker positioned on the network can read, modify, or replay packets without the sender or receiver detecting the interference.",
    cia: ["Confidentiality"],
    vs: ["Velocity", "Value"],
    severity: "High",
    likelihood: 4,
    impact: 4,
    mitre: "T1557",
    controls: "Enforce mTLS across all producer-broker connections, implement certificate pinning, rotate certificates on a defined schedule."
  },
  {
    id: "T03",
    layer: "Ingestion",
    threat: "DDoS on Ingestion Endpoints",
    description: "A volumetric flood targeting streaming APIs or Kafka brokers causes pipeline starvation, data loss, and processing backlogs. At high velocity, even brief disruptions cascade into significant data gaps in the warehouse.",
    cia: ["Availability"],
    vs: ["Volume", "Velocity", "Variability"],
    severity: "High",
    likelihood: 4,
    impact: 4,
    mitre: "T1498",
    controls: "Implement rate limiting and backpressure policies on brokers, configure auto-scaling on ingestion nodes, use upstream traffic filtering and DDoS mitigation services."
  },
  {
    id: "T04",
    layer: "Ingestion",
    threat: "Data Source Spoofing",
    description: "An adversary impersonates a legitimate data producer to inject forged or manipulated records into the pipeline. The forged data passes downstream undetected, corrupting analytics outputs and any ML models trained on that data.",
    cia: ["Integrity", "Confidentiality"],
    vs: ["Veracity", "Variety"],
    severity: "High",
    likelihood: 3,
    impact: 5,
    mitre: "T1078",
    controls: "Enforce mutual authentication on all data sources, implement digital signatures for record provenance, track lineage from source to storage."
  },
  {
    id: "T05",
    layer: "Ingestion",
    threat: "Unauthenticated Broker Access",
    description: "Message brokers deployed without authentication allow any actor on the network to freely publish messages or consume existing ones. This is a frequent misconfiguration in internal Kafka clusters where developers disable auth for convenience.",
    cia: ["Confidentiality", "Integrity"],
    vs: ["Value", "Volume"],
    severity: "Critical",
    likelihood: 4,
    impact: 5,
    mitre: "T1133",
    controls: "Enable SASL/SCRAM or mTLS authentication on all brokers, enforce per-topic ACLs, segment broker networks from general-purpose infrastructure."
  },
  {
    id: "T06",
    layer: "Ingestion",
    threat: "Schema Poisoning",
    description: "An attacker with write access to the schema registry pushes a malformed or deliberately altered schema. Downstream processors that rely on the registry silently misparse or discard records, causing data loss or integrity corruption without raising errors.",
    cia: ["Integrity"],
    vs: ["Variety", "Veracity"],
    severity: "Medium",
    likelihood: 2,
    impact: 4,
    mitre: "T1565",
    controls: "Restrict schema registry write access with role-based controls, enforce schema versioning with mandatory review before promotion, maintain rollback capability."
  },

  // ── STORAGE ────────────────────────────────────────────────────────────────
  {
    id: "T07",
    layer: "Storage",
    threat: "Misconfigured Cloud Buckets and HDFS",
    description: "Publicly accessible S3 buckets or HDFS NameNodes expose entire datasets to the internet due to overly permissive ACLs. This is consistently the leading cause of large-scale Big Data breaches, often discovered by automated scanners before the organisation notices.",
    cia: ["Confidentiality"],
    vs: ["Volume", "Value"],
    severity: "Critical",
    likelihood: 5,
    impact: 5,
    mitre: "T1530",
    controls: "Enforce deny-public-access policies at the organisation level, run continuous CSPM scanning, audit HDFS ACLs on a weekly schedule, enable S3 Block Public Access across all accounts."
  },
  {
    id: "T08",
    layer: "Storage",
    threat: "Unencrypted Data at Rest",
    description: "Sensitive datasets stored in plaintext on HDFS, NoSQL databases, or object storage become immediately readable if an attacker gains storage-level access. This affects both active data and older cold storage tiers that are rarely audited.",
    cia: ["Confidentiality"],
    vs: ["Value", "Volume"],
    severity: "Critical",
    likelihood: 4,
    impact: 5,
    mitre: "T1005",
    controls: "Enable AES-256 encryption at rest across all storage tiers, use HDFS Transparent Data Encryption for Hadoop environments, enforce encryption as a mandatory policy in cloud storage bucket configuration."
  },
  {
    id: "T09",
    layer: "Storage",
    threat: "Ransomware and Destructive Malware",
    description: "Malware deployed on data lake nodes encrypts or deletes petabyte-scale datasets, rendering analytics infrastructure unusable. Recovery without immutable backups can take weeks and may result in permanent data loss.",
    cia: ["Availability", "Integrity"],
    vs: ["Volume", "Value"],
    severity: "Critical",
    likelihood: 3,
    impact: 5,
    mitre: "T1486",
    controls: "Maintain immutable offsite backups with tested restoration procedures, deploy endpoint detection and response on all storage nodes, enforce network segmentation to limit lateral movement."
  },
  {
    id: "T10",
    layer: "Storage",
    threat: "Privilege Escalation on Data Lake",
    description: "Misconfigured RBAC policies or Kerberos delegation settings allow a low-privilege analyst account to escalate to admin rights, gaining full read, write, and delete access to the data lake.",
    cia: ["Confidentiality", "Integrity"],
    vs: ["Value", "Volume"],
    severity: "High",
    likelihood: 3,
    impact: 5,
    mitre: "T1068",
    controls: "Apply principle of least privilege, harden Kerberos delegation settings, deploy a Privileged Access Management solution, conduct quarterly access reviews."
  },
  {
    id: "T11",
    layer: "Storage",
    threat: "Insecure Key Management",
    description: "Encryption keys stored alongside encrypted data or hardcoded in environment variables nullify all encryption protections. If an attacker obtains storage access, they find both the ciphertext and the key in the same location.",
    cia: ["Confidentiality"],
    vs: ["Value"],
    severity: "High",
    likelihood: 3,
    impact: 5,
    mitre: "T1552",
    controls: "Store all keys in a dedicated KMS such as AWS KMS or HashiCorp Vault, enforce automatic key rotation, never co-locate keys with the data they protect."
  },
  {
    id: "T12",
    layer: "Storage",
    threat: "Backup Compromise and Exfiltration",
    description: "Backup repositories are often monitored less rigorously than primary storage, making them attractive secondary exfiltration targets. Attackers that fail to access live data will pivot to backups.",
    cia: ["Confidentiality"],
    vs: ["Volume", "Value"],
    severity: "Medium",
    likelihood: 3,
    impact: 4,
    mitre: "T1537",
    controls: "Encrypt all backups independently, enforce strict access controls on backup systems, log all access, maintain air-gapped copies for critical datasets."
  },

  // ── PROCESSING ─────────────────────────────────────────────────────────────
  {
    id: "T13",
    layer: "Processing",
    threat: "Spark and MapReduce Job Injection",
    description: "An unauthorised actor submits a malicious computation job to YARN or a Spark cluster, using the cluster's own compute resources to exfiltrate data, enumerate the data lake, or execute arbitrary code at scale.",
    cia: ["Integrity", "Confidentiality"],
    vs: ["Velocity", "Volume"],
    severity: "High",
    likelihood: 3,
    impact: 5,
    mitre: "T1059",
    controls: "Restrict job submission to authorised principals only, enforce YARN queue-level ACLs, require signed job artifacts, audit all submitted jobs."
  },
  {
    id: "T14",
    layer: "Processing",
    threat: "Insecure Deserialization",
    description: "Processing pipelines that deserialize untrusted data formats such as Avro, Thrift, or Java serialized objects without validation are vulnerable to remote code execution. A crafted payload triggers execution on the processing node during deserialization.",
    cia: ["Integrity", "Confidentiality"],
    vs: ["Variety", "Velocity"],
    severity: "High",
    likelihood: 3,
    impact: 5,
    mitre: "T1059.007",
    controls: "Prefer safe serialization formats such as JSON or Protobuf, implement deserialization filters that reject unknown classes, keep processing libraries patched."
  },
  {
    id: "T15",
    layer: "Processing",
    threat: "Resource Exhaustion and Cryptojacking",
    description: "An attacker with cluster access deploys unauthorised cryptomining workloads, consuming CPU and memory that starves legitimate jobs. Processing pipelines slow or fail while the attacker profits from the stolen compute.",
    cia: ["Availability"],
    vs: ["Volume", "Velocity", "Variability"],
    severity: "Medium",
    likelihood: 3,
    impact: 3,
    mitre: "T1496",
    controls: "Enforce per-job resource quotas, monitor for anomalous CPU usage patterns, isolate workloads using containers or VMs, alert on unexpected long-running jobs."
  },
  {
    id: "T16",
    layer: "Processing",
    threat: "Side-Channel Data Leakage",
    description: "Co-located processing jobs on shared infrastructure can leak sensitive intermediate computation results through timing variations, shared memory, or CPU cache state. This is particularly relevant in multi-tenant analytics environments.",
    cia: ["Confidentiality"],
    vs: ["Value", "Variability"],
    severity: "Medium",
    likelihood: 2,
    impact: 4,
    mitre: "T1040",
    controls: "Enforce workload isolation with dedicated nodes for sensitive jobs, evaluate trusted execution environments, apply noise injection techniques where applicable."
  },
  {
    id: "T17",
    layer: "Processing",
    threat: "Insecure Inter-node Communication",
    description: "The Hadoop shuffle phase and other inter-node data transfers operate in plaintext by default. A passive attacker on the internal network can capture intermediate computation results, which may contain sensitive business data.",
    cia: ["Confidentiality", "Integrity"],
    vs: ["Velocity", "Volume"],
    severity: "High",
    likelihood: 3,
    impact: 4,
    mitre: "T1040",
    controls: "Enable encryption on Hadoop shuffle traffic, enforce TLS 1.3 on all cluster inter-node communications, audit network configurations during cluster provisioning."
  },

  // ── ANALYSIS ───────────────────────────────────────────────────────────────
  {
    id: "T18",
    layer: "Analysis",
    threat: "ML Model Poisoning",
    description: "Adversarial training data injected during batch ingestion subtly corrupts model behaviour over time. A fraud detection model, for example, can be trained to ignore patterns associated with a specific type of attack, creating a persistent blind spot.",
    cia: ["Integrity"],
    vs: ["Veracity", "Value"],
    severity: "Critical",
    likelihood: 3,
    impact: 5,
    mitre: "T1565.001",
    controls: "Validate training data provenance before each training run, implement model drift monitoring, run periodic adversarial audits against deployed models, maintain versioned clean training datasets."
  },
  {
    id: "T19",
    layer: "Analysis",
    threat: "SQL and SparkSQL Injection",
    description: "Malicious query strings submitted through Hive, Presto, or Impala interfaces extract, modify, or delete warehouse data. Analytics portals with dynamic query construction and insufficient input sanitization are particularly vulnerable.",
    cia: ["Confidentiality", "Integrity"],
    vs: ["Variety", "Value"],
    severity: "High",
    likelihood: 4,
    impact: 4,
    mitre: "T1190",
    controls: "Use parameterized queries throughout, enforce ORM-based data access, deploy a WAF in front of query interfaces, sandbox query execution environments."
  },
  {
    id: "T20",
    layer: "Analysis",
    threat: "Re-identification and Inference Attacks",
    description: "An attacker combines published anonymized aggregate data with auxiliary public information to re-identify specific individuals. This is a direct violation of GDPR, NDPR, and HIPAA, and frequently occurs in health, finance, and location datasets.",
    cia: ["Confidentiality"],
    vs: ["Value", "Veracity", "Variety"],
    severity: "High",
    likelihood: 4,
    impact: 5,
    mitre: "T1590",
    controls: "Apply differential privacy to all published aggregates, enforce k-anonymity on datasets before release, implement data masking on PII fields, restrict access to raw granular data."
  },
  {
    id: "T21",
    layer: "Analysis",
    threat: "Unauthorized Analytics Access",
    description: "Overprivileged analyst accounts or shared team credentials allow unauthorized parties to query sensitive datasets. This is frequently caused by convenience-driven account sharing rather than deliberate malice.",
    cia: ["Confidentiality"],
    vs: ["Value"],
    severity: "High",
    likelihood: 3,
    impact: 4,
    mitre: "T1078",
    controls: "Enforce RBAC on all analytics platforms, mandate MFA for all analyst accounts, implement query audit logging with alerting on sensitive table access."
  },
  {
    id: "T22",
    layer: "Analysis",
    threat: "Adversarial Model Evasion",
    description: "Carefully crafted inputs are designed to evade ML-based anomaly detectors or classification models, allowing attackers to perform malicious actions that the model consistently misclassifies as benign.",
    cia: ["Integrity"],
    vs: ["Veracity", "Variability"],
    severity: "Medium",
    likelihood: 2,
    impact: 4,
    mitre: "T1562",
    controls: "Train models with adversarial robustness techniques, use ensemble models to reduce evasion effectiveness, implement human-in-the-loop review for high-stakes model decisions."
  },

  // ── SERVING ────────────────────────────────────────────────────────────────
  {
    id: "T23",
    layer: "Serving",
    threat: "Broken Object-Level Access Control",
    description: "Serving APIs fail to enforce per-record authorization, meaning a request authenticated as User A can retrieve records belonging to User B simply by manipulating identifiers in the request. This is consistently ranked as the top API security risk.",
    cia: ["Confidentiality"],
    vs: ["Value", "Volume"],
    severity: "Critical",
    likelihood: 4,
    impact: 5,
    mitre: "T1078",
    controls: "Implement fine-grained authorization using OPA or a Zanzibar-model system, validate object ownership on every request, never trust client-supplied identifiers without server-side verification."
  },
  {
    id: "T24",
    layer: "Serving",
    threat: "Data Exfiltration via Bulk Export",
    description: "Legitimate bulk export features such as CSV downloads and data dump APIs are abused by malicious insiders or compromised accounts to exfiltrate entire datasets. The action appears routine in logs and often goes unnoticed.",
    cia: ["Confidentiality"],
    vs: ["Volume", "Value"],
    severity: "High",
    likelihood: 4,
    impact: 5,
    mitre: "T1048",
    controls: "Enforce export size limits, require approval workflows for large exports, deploy DLP scanning on all outbound data flows, alert on anomalous export volume for any single account."
  },
  {
    id: "T25",
    layer: "Serving",
    threat: "Exposed BI Dashboard",
    description: "Business intelligence tools such as Apache Superset and Grafana deployed with default credentials or without authentication expose real-time business KPIs, operational metrics, and sensitive trend data to unauthenticated visitors.",
    cia: ["Confidentiality"],
    vs: ["Value"],
    severity: "High",
    likelihood: 4,
    impact: 4,
    mitre: "T1133",
    controls: "Integrate BI tools with SSO/OIDC, disable all public embedding features, change all default credentials at deployment time, place BI tools behind VPN or internal network access controls."
  },
  {
    id: "T26",
    layer: "Serving",
    threat: "API Rate Limit Bypass and Scraping",
    description: "Attackers rotate IPs, tokens, or user agents to bypass API rate limits and incrementally harvest entire datasets over time. Individual requests appear legitimate while the aggregate constitutes full exfiltration.",
    cia: ["Availability", "Confidentiality"],
    vs: ["Velocity", "Volume"],
    severity: "Medium",
    likelihood: 3,
    impact: 3,
    mitre: "T1595",
    controls: "Implement adaptive rate limiting based on behavioral patterns, enforce IP reputation scoring, use token bucket algorithms, monitor for distributed low-rate harvesting patterns."
  },
  {
    id: "T27",
    layer: "Serving",
    threat: "XSS on BI and Reporting Tools",
    description: "Stored or reflected cross-site scripting vulnerabilities in self-service reporting tools allow attackers to inject scripts that hijack authenticated analyst sessions, granting access to all data the analyst can query.",
    cia: ["Confidentiality", "Integrity"],
    vs: ["Value"],
    severity: "Medium",
    likelihood: 3,
    impact: 4,
    mitre: "T1059.007",
    controls: "Enforce strict Content Security Policy headers, apply output encoding on all rendered fields, maintain a regular patch cadence for all BI tool deployments."
  },
  {
    id: "T28",
    layer: "Serving",
    threat: "Excessive Data Exposure in API Responses",
    description: "Serving APIs return complete object payloads including sensitive fields that the requesting client does not need or have rights to see. This violates data minimization principles and enables passive harvesting of sensitive attributes.",
    cia: ["Confidentiality"],
    vs: ["Value", "Volume", "Variety"],
    severity: "High",
    likelihood: 4,
    impact: 4,
    mitre: "T1213",
    controls: "Implement server-side response field filtering, enforce GraphQL query depth and field limits, define explicit API response schemas that exclude sensitive fields by default."
  }
];


const SIX_VS = [
  {
    v: "Volume",
    score: 88,
    summary: "Petabyte-scale data creates massive attack surfaces and makes anomaly detection computationally expensive.",
    detail: "The scale of Big Data storage means a single misconfiguration can expose billions of records instantly. Cold storage and archival systems expand the surface further because they are audited less frequently than hot data. Volume also makes comprehensive log analysis impractical without dedicated SIEM infrastructure."
  },
  {
    v: "Velocity",
    score: 76,
    summary: "Real-time streaming leaves minimal time for validation, enabling injection attacks to propagate before detection.",
    detail: "High-throughput pipelines built on Kafka, Apache Flink, and Spark Streaming process millions of events per second. Traditional synchronous security controls cannot operate at this speed. By the time a malicious record is detected, thousands of downstream consumers may have already processed it."
  },
  {
    v: "Variety",
    score: 72,
    summary: "Heterogeneous data formats expand the attack surface through unvalidated parsing pipelines.",
    detail: "Each format such as JSON, CSV, Avro, Parquet, and binary media requires a different parser. Every parser is a potential attack vector. Malformed files can trigger buffer overflows, silent data corruption, or remote code execution depending on the library used. Unstructured data like images and documents introduces additional risks."
  },
  {
    v: "Veracity",
    score: 82,
    summary: "Low data trustworthiness enables poisoning attacks where corrupt inputs produce corrupt outputs.",
    detail: "Without data provenance and integrity checks at ingestion, adversaries can inject false data upstream and watch it propagate through the entire analytics stack undetected. ML models are particularly vulnerable because they learn statistical patterns from training data. Poisoned training data creates persistent, hard-to-detect model vulnerabilities."
  },
  {
    v: "Value",
    score: 94,
    summary: "High-value datasets are prime targets for APTs, insiders, and ransomware groups.",
    detail: "Big Data environments aggregate PII, financial records, health data, and proprietary business intelligence in one place. This concentration of high-value data attracts well-resourced adversaries including nation-state actors. The value dimension scores highest because it determines attacker motivation and the resources they will invest in a breach."
  },
  {
    v: "Variability",
    score: 65,
    summary: "Unpredictable data flow patterns create blind spots in anomaly detection systems.",
    detail: "Inconsistent data volumes and formats make it difficult to define a reliable baseline for normal behavior. Anomaly detectors tuned for steady-state traffic generate excessive false positives during natural spikes, leading operations teams to disable or ignore alerts. This creates windows of reduced visibility that attackers can exploit."
  }
];


const RECOMMENDATIONS = [
  {
    priority: "P1",
    title: "Encrypt all data at rest and in transit",
    layer: "Storage / Processing",
    effort: "Medium",
    body: "Unencrypted HDFS, S3 buckets, and cluster shuffle traffic are the highest-impact, fastest-to-fix hardening targets. Enable AES-256 encryption at rest across all storage tiers and enforce TLS 1.3 on all inter-node and producer-broker communications. This directly addresses T07, T08, and T17."
  },
  {
    priority: "P1",
    title: "Audit and lock down all cloud storage ACLs",
    layer: "Storage",
    effort: "Low",
    body: "Misconfigured bucket and HDFS permissions are the most common cause of Big Data breaches. Enable S3 Block Public Access at the organisation level, run automated CSPM scans on a continuous basis, and review HDFS ACLs weekly. This is low effort and directly addresses T07 which carries a maximum risk score."
  },
  {
    priority: "P1",
    title: "Enforce authentication on all brokers and APIs",
    layer: "Ingestion / Serving",
    effort: "Medium",
    body: "Unauthenticated Kafka brokers and unprotected serving APIs are open entry points. Enable SASL/SCRAM or mTLS on all brokers, enforce SSO and MFA on all serving interfaces, and require per-topic ACLs. This directly addresses T01, T05, and T25."
  },
  {
    priority: "P1",
    title: "Implement RBAC and least privilege across all layers",
    layer: "All Layers",
    effort: "High",
    body: "Overprivileged accounts across ingestion, storage, processing, and serving layers are a common thread in multiple identified threats. Deploy Apache Ranger for Hadoop-layer authorisation, use OPA for API-level decisions, and conduct a quarterly access review process."
  },
  {
    priority: "P2",
    title: "Deploy data provenance and lineage tracking",
    layer: "Ingestion / Analysis",
    effort: "High",
    body: "Without lineage tracking, data poisoning and source spoofing go undetected. Implement Apache Atlas or OpenLineage to record the full journey of every dataset from source to consumption. This is essential for investigating T04 and T18 class incidents."
  },
  {
    priority: "P2",
    title: "Apply differential privacy to all published analytics",
    layer: "Analysis",
    effort: "High",
    body: "Re-identification attacks on anonymised datasets constitute a breach under GDPR, NDPR, and HIPAA even if no raw PII was directly exposed. Apply differential privacy with a defined epsilon budget and enforce k-anonymity thresholds before any aggregate data is published or shared externally."
  },
  {
    priority: "P2",
    title: "Enable centralised audit logging and SIEM integration",
    layer: "All Layers",
    effort: "Medium",
    body: "Threat detection across five ecosystem layers requires centralised visibility. Forward cluster logs, query audit logs, API access logs, and export logs to a SIEM platform. Configure alerts for anomalous export volumes, privilege escalation events, and failed authentication bursts."
  },
  {
    priority: "P2",
    title: "Harden the ML training pipeline against poisoning",
    layer: "Analysis",
    effort: "High",
    body: "Model poisoning attacks are subtle and long-lasting. Validate data provenance before each training run, implement continuous drift monitoring on deployed models, and maintain a versioned clean training dataset that can be used for emergency retraining if poisoning is detected."
  },
  {
    priority: "P3",
    title: "Implement API response filtering and DLP controls",
    layer: "Serving",
    effort: "Medium",
    body: "Over-exposed API responses and unrestricted bulk exports are passive exfiltration vectors. Define explicit response schemas that exclude sensitive fields by default, enforce export size caps with approval workflows, and deploy DLP scanning on all outbound serving-layer data flows."
  },
  {
    priority: "P3",
    title: "Deploy runtime anomaly detection on the processing cluster",
    layer: "Processing",
    effort: "Medium",
    body: "Cryptojacking and unauthorised job submissions are difficult to catch without established behavioural baselines. Monitor CPU and memory usage patterns per queue, enforce signed job artifact requirements, and alert on any job submitted outside defined working hours or by unexpected principals."
  },
  {
    priority: "P3",
    title: "Conduct regular adversarial testing and red team exercises",
    layer: "All Layers",
    effort: "High",
    body: "Documented controls must be validated empirically. Run Big Data-focused red team exercises that include injection attacks on ingestion APIs, SparkSQL injection through analytics portals, and social engineering attempts targeting analyst credentials. Re-test after any major infrastructure change."
  }
];
