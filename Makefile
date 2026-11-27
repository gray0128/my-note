.PHONY: help eval-selftest eval-fast eval-contract eval-ui eval-all

PYTHON ?= python3
E2E_PYTHON ?= $(shell $(PYTHON) -c "import playwright" >/dev/null 2>&1 && echo "$(PYTHON)" || echo "uv run --with playwright $(PYTHON)")

help:
	@echo "my-note Verification & Eval Harness (Layer 3 Deterministic Ceiling)"
	@echo "  make eval-selftest  Tier 0 (<3s):   Mutant self-tests for static & golden verifiers"
	@echo "  make eval-fast      Tier 0 (<15s):  Selftest + architecture/budget guards + fmt + regression seeds"
	@echo "  make eval-contract  Tier 1 (<90s):  Proptest + M1/M2 DST + CLI golden + web & workerd contract suites"
	@echo "  make eval-ui        Tier 1 (<120s): Real daemon + wrangler dev + Chromium/WebKit SEC & CDP equivalence"
	@echo "  make eval-all       Full local gate (eval-contract + eval-ui)"

eval-selftest:
	$(PYTHON) scripts/check-architecture.py --selftest
	@if grep -q -- '--selftest' evals/golden/run_golden.py; then \
		./evals/golden/run_golden.sh --selftest; \
	fi

eval-fast: eval-selftest
	$(PYTHON) scripts/check-architecture.py
	cargo fmt --all -- --check
	cargo test -p mynote-core replay_all_active_regression_seeds_from_evals

eval-contract: eval-fast
	pnpm --dir web typecheck && pnpm --dir web test
	pnpm --dir web build && pnpm --dir web build:pwa
	pnpm --dir cloud-cf typecheck && pnpm --dir cloud-cf test
	cargo clippy --workspace --all-targets -- -D warnings
	MYNOTE_DST_SEEDS=$${MYNOTE_DST_SEEDS:-100} cargo test --workspace
	cargo check -p mynote-core --target wasm32-unknown-unknown
	cargo check -p mynote-wasm --target wasm32-unknown-unknown --no-default-features --features desktop
	cargo check -p mynote-wasm --target wasm32-unknown-unknown --no-default-features --features pwa
	cargo build --bin mynote
	./evals/golden/run_golden.sh

eval-ui:
	pnpm --dir web build && pnpm --dir web build:pwa
	cargo build --bin mynote
	$(PYTHON) tests/e2e/test_m2_cli_pty_vault_shred.py
	$(E2E_PYTHON) tests/e2e/test_m2_sec03_desktop_chromium.py
	$(E2E_PYTHON) tests/e2e/test_m2_sec08_mobile_webkit.py
	$(E2E_PYTHON) tests/e2e/test_m3_sec06_pele_history.py
	$(E2E_PYTHON) tests/e2e/test_ui_cdp_equivalence.py
	$(E2E_PYTHON) tests/e2e/test_m4_clip_sec08_sec09.py

eval-all: eval-contract eval-ui
