# Architecture — P-068

> Tài liệu này định nghĩa **hệ thống được tổ chức và chạy như thế nào**. Không định nghĩa lại scope sản phẩm, payload hay ownership.

## 1. System Overview

```mermaid
flowchart TB
    subgraph Client["Client"]
        UI["React Web App"]
        Admin["Admin Review UI"]
    end
    subgraph Backend["FastAPI Backend"]
        API["REST + WebSocket"]
        Services["Analysis, Review, Audit"]
    end
    subgraph Agent["LangGraph Worker"]
        Graph["Orchestrator"]
        Risk["Deterministic Risk Engine"]
        Adapters["Tool Adapters + SSRF Guard"]
    end
    subgraph Data["Private Data Layer"]
        DB[("PostgreSQL + pgvector")]
        Redis[("Redis")]
    end
    subgraph External["External Providers"]
        Reputation["URL Reputation"]
        FactCheck["Fact-check Sources"]
        LLM["LLM API"]
    end

    UI --> API
    Admin --> API
    API --> Services
    Services <--> DB
    API <--> Redis
    Graph <--> Redis
    Graph --> Risk
    Graph --> Adapters
    Adapters --> Reputation
    Adapters --> FactCheck
    Graph --> LLM
    Graph <--> DB
```

Dependency direction trong code: `api → application service → agents graph → agents.tools protocol → adapter`. Node không import provider SDK; API không biết raw provider response.

## 2. Agent Flow

```mermaid
flowchart TB
    Start(["Analysis queued"]) --> Validate["Validate and classify"]
    Validate --> Extract["Extract URLs and claims"]
    Extract --> Rules["Normalize + local rules + blacklist"]
    Rules --> Enough{"Enough evidence?"}
    Enough -->|"No"| Plan["Select next allowed tool"]
    Plan --> Consent{"External URL scan needs consent?"}
    Consent -->|"No consent"| Limit["Record limitation"]
    Consent -->|"Allowed / not required"| Tool["Call adapter"]
    Tool --> Observe["Normalize evidence"]
    Observe --> Stop{"Enough or budget exhausted?"}
    Stop -->|"Continue"| Plan
    Stop -->|"Stop"| Score["Deterministic assessment"]
    Limit --> Score
    Enough -->|"Yes"| Score
    Score --> Explain["Grounded explanation"]
    Explain --> Escalate{"Review required?"}
    Escalate -->|"No"| Done(["Return result"])
    Escalate -->|"Yes"| Review["Create pending review case"]
    Review --> Done
```

Vòng lặp dừng khi evidence đủ, hết tool calls/retries, vượt time/cost budget hoặc không còn tool phù hợp. Tool lỗi được chuẩn hóa thành error/limitation; không trở thành tín hiệu an toàn.

## 3. Deployment

```mermaid
flowchart TB
    Browser["User/Admin Browser"] -->|"HTTPS/WSS"| Edge["TLS Endpoint"]
    subgraph Runtime["Railway Private Project"]
        Web["Web Container"]
        API["API Container"]
        Worker["Agent Worker"]
        DB[("PostgreSQL + pgvector")]
        Redis[("Redis")]
    end
    Edge --> Web
    Edge --> API
    Web --> API
    API <--> DB
    API <--> Redis
    Worker <--> Redis
    Worker <--> DB
    Worker -->|"HTTPS egress"| Providers["LLM, reputation, fact-check"]
```

- Chỉ Web/API public; Worker, Redis và DB nằm trong private network.
- API enqueue job và phát status; Worker thực thi graph, persist state/evidence.
- Secrets được inject server-side. Browser không gọi trực tiếp provider.
- CI build immutable images, chạy test/migration rồi deploy; DB dùng persistent storage và backup.

## 4. Security boundaries

- URL adapter validate scheme/host, resolve DNS, chặn loopback/private/link-local/multicast/cloud-metadata trước request và sau mỗi redirect.
- Redirect count, response size, timeout, retry, rate và tool budget bị giới hạn.
- AuthN ở API; ownership/RBAC được kiểm tra trước đọc analysis hoặc admin action.
- Message chỉ đi đến thành phần cần thiết; log dùng ID/latency/status và redaction dữ liệu nhạy cảm.
- LLM chỉ nhận context tối thiểu và output có schema; Risk Engine không dùng output tự do làm điểm.
- Blacklist write chỉ nằm sau admin authorization và audit transaction.

## 5. Repository mapping

```text
src/
├── agents/         # state, graph, nodes, tool protocols, adapters and network safety
├── api/            # REST, WebSocket, auth dependencies
├── services/       # analysis/review use cases
├── repositories/   # persistence implementations
├── models/         # shared Pydantic contracts
└── core/           # config, logging, security utilities
tests/{unit,integration,contract,eval,fixtures}/
eval/{datasets,scripts}/
```

Giữ package hiện tại `src/agents` làm nơi duy nhất cho orchestration và tool boundary. Tool protocol, fake adapter, provider adapter và network safety được tách thành các module trong `src/agents/tools/`; `src/services` và `src/repositories` được thêm ở top level để tách use case và persistence khỏi agent.
