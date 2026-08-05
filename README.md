voicedna/                                                                                                                                                                                    
├── backend/                     the enclave engine (one deployable)                                                                                                                         
│   ├── daemons/                 always-on mail-processing runtime                                                                                                                           
│   │   ├── daemon_loop.py         FIFO listener; drains wake spool, runs pipeline per account                                                                                               
│   │   ├── wake_queue.py          per-account wake spool (enqueue/drain, coalesces pushes)
│   │   ├── pipeline.py            process_account: fetch Gmail delta, route, draft, advance cursor                                                                                          
│   │   └── gmail_hook_server.py   HTTPS webhook; verifies Pub/Sub OIDC JWT, enqueues a wake                                                                                                 
│   ├── drafting/                the "brain": emails in, drafts/summaries/events out                                                                                                         
│   │   ├── agentic_drafter.py     LLM tool-loop drafter                                                                                                                                     
│   │   ├── draft_replies.py       reply drafting; owns VOICE_PROFILE; the create_draft boundary                                                                                             
│   │   ├── manual_draft.py        hand-invoked draft for one specific thread                                                                                                                
│   │   ├── schedule_from_sent.py  detect scheduling intent, create calendar events
│   │   ├── tool_executors.py      tools the agent may call (search gmail, list calendar, get thread)                                                                                        
│   │   └── email_summary.py       daily digest: fetch + summarise + Telegram (cron)
│   ├── masking/                 the security kernel                                                                                                                                         
│   │   ├── pseudonymizer.py       PII mask/unmask; only masked text may cross to the LLM
│   │   └── masking_eval/          labeled PII corpus + recall evaluator                                                                                                                     
│   ├── billing/                 Polar subscription context (gates account active/inactive)                                                                                                  
│   │   ├── billing.py             PolarBilling; flips plan_status in the account store                                                                                                      
│   │   ├── polar_api.py           Polar REST client (checkout, portal)                                                                                                                      
│   │   ├── billing_webhook.py     Polar order.paid/subscription webhook receiver (daemon)
│   │   └── billing_poller.py      reconciliation poller (timer)                                                                                                                             
│   ├── integrations/            adapters to external systems (talk to the outside world)
│   │   ├── telegram.py            Telegram sender (send_telegram, notify_error)
│   │   ├── llm_client.py          LLM adapter; complete() masks -> calls provider -> restores
│   │   └── gmail_gcal/            the only place that touches raw Gmail/Calendar
│   │       ├── oauth_app.py         the OAuth app itself: client keys, scopes, endpoints
│   │       ├── gmail_api.py         Gmail client + messages/threads/history/watch
│   │       ├── calendar_api.py      calendar list + insert
│   │       ├── mailbox.py           history-delta and daily fetches
│   │       └── drafts.py            RFC822 assembly + drafts.create/update
│   ├── custody/                 split custody of the Gmail refresh token
│   │   ├── wrapping.py            inner AES-GCM layer, keyed from the enclave's KMS secret
│   │   ├── client.py              mTLS RPC to the co-signer, which holds the outer layer
│   │   └── tokens.py              access tokens: unwrap, sign, refresh, cache, zeroize
│   ├── accounts/                the datastore API (code, not data)
│   │   ├── account.py             Account object + load_accounts()
│   │   └── state.py               per-user history cursor (StateStore)
│   └── paths.py                 single source of truth for on-disk locations (.env, database)
│                                                                 
├── frontend/                    NEW: server-rendered webapp (OAuth, sessions, settings,                                                                                                     
│                                voice DNA, billing UI) — see docs/plan_webapp.md                                                                                                       
│                                                                                                                                                                                            
├── database/                   git-ignored account store: accounts.json + per-user token/state                                                                                              
│                               (persistent data only; fifo/locks/logs are runtime scratch, not here)                                                                                        
│                                                                                                                                                                                            
├── deploy/                     build / ship / run                                                                                                                                           
│   ├── deploy.sh                 rsync to Hetzner + systemd restart                                                                                                                         
│   ├── run_daemon.sh             local launcher for daemon_loop                                                                                                                             
│   ├── hetzner/                  systemd units + timers + Caddyfile
│   └── phala/                    Nix/uv image build (pyproject, uv.lock, docker-compose, IMAGE_HASH)                                                                                        
│                                                                 
├── tests/                      test suite                                                                                                                                                   
├── docs/                       plan.md, R_results.txt, graphviz diagrams                                                                                                                    
│
│  # repo-root config/manifests (stay at root by convention):                                                                                                                                
├── flake.nix, flake.lock       Nix build entrypoint (appCode = ./.)                                                                                                                         
├── requirements.txt            Python deps                                                                                                                                                  
├── CLAUDE.md                   repo instructions                                                                                                                                            
└── .env                        secrets, git-ignored                                                                                                                                         
