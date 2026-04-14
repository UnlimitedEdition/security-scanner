## What this PR does

<!-- Brief description of the change. What problem does it solve? -->

## Why

<!-- Explain the motivation. What was broken or missing? Link to an issue if applicable. -->

Closes #

## Type of change

- [ ] `feat` — New feature or check module
- [ ] `fix` — Bug fix
- [ ] `security` — Security-related fix
- [ ] `docs` — Documentation change
- [ ] `refactor` — Code change that neither fixes a bug nor adds a feature
- [ ] `test` — Adding or fixing tests
- [ ] `deps` — Dependency update
- [ ] `ci` — CI/CD change

## How to test

<!-- Step-by-step instructions to verify the change works correctly -->

1. 
2. 
3. 

## Checklist

### General
- [ ] My code follows the existing style in `scanner.py` / `checks/`
- [ ] I have added the `SPDX-License-Identifier: MIT` header to new files
- [ ] I have updated documentation if applicable
- [ ] My changes generate no new warnings

### Security (required for all changes)
- [ ] No hardcoded secrets, API keys, or credentials
- [ ] All outbound HTTP requests use `safe_get()` / `safe_head()` / `safe_post()`
- [ ] No bypass of SSRF, rate limiting, or ownership verification
- [ ] Input validation on all user-provided data

### If adding a new check module
- [ ] Module has both Serbian and English strings
- [ ] Finding IDs are unique and follow `category_detail` pattern
- [ ] Exception handling: crashes don't propagate to scanner
- [ ] Check is registered in `scanner.py` with correct tier (`safe`/`full`/`redacted`)
- [ ] At least one test case included in `tests/`
- [ ] `ARCHITECTURE.md` updated with the new module

### If modifying scoring
- [ ] `tests/test_strictness.py` updated to match new expectations
- [ ] `standard` profile behavior documented if changed (V3 regression gate)

## Screenshots (if applicable)

<!-- Add screenshots for UI changes or scan result differences -->
